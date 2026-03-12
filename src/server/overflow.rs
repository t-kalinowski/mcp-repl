use std::collections::VecDeque;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;

use crate::output_capture::OUTPUT_RING_CAPACITY_BYTES;
use crate::pager::{self, Pager};
use crate::reply_overflow::{ReplyOverflowBehavior, ReplyOverflowSettings};
use crate::worker_protocol::{TextStream, WorkerContent, WorkerReply};

static REPLY_FILES_ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Default)]
pub(crate) struct ReplyFilesManager {
    root: Option<PathBuf>,
    next_sequence: u64,
    dirs: VecDeque<PathBuf>,
}

impl ReplyFilesManager {
    pub(crate) fn new() -> std::io::Result<Self> {
        Ok(Self {
            root: Some(build_reply_files_root()?),
            next_sequence: 0,
            dirs: VecDeque::new(),
        })
    }

    pub(crate) fn clear(&mut self) -> std::io::Result<()> {
        if let Some(root) = self.root.take() {
            let _ = std::fs::remove_dir_all(&root);
        }
        self.root = Some(build_reply_files_root()?);
        self.next_sequence = 0;
        self.dirs.clear();
        Ok(())
    }

    pub(crate) fn apply_to_reply(
        &mut self,
        reply: WorkerReply,
        settings: &ReplyOverflowSettings,
    ) -> WorkerReply {
        if settings.behavior != ReplyOverflowBehavior::Files {
            return reply;
        }

        match reply {
            WorkerReply::Output {
                contents,
                is_error,
                error_code,
                prompt,
                prompt_variants,
                text_overflow,
            } => {
                let contents = render_files_reply_contents(
                    self,
                    contents,
                    prompt.as_deref(),
                    settings,
                    text_overflow.as_ref(),
                );
                WorkerReply::Output {
                    contents,
                    is_error,
                    error_code,
                    prompt,
                    prompt_variants,
                    text_overflow,
                }
            }
        }
    }

    fn next_reply_dir(&mut self, retention_max_dirs: usize) -> std::io::Result<PathBuf> {
        if self.root.is_none() {
            self.root = Some(build_reply_files_root()?);
        }
        self.next_sequence = self.next_sequence.saturating_add(1);
        let dir = self
            .root
            .as_ref()
            .expect("reply files root should be initialized")
            .join(format!("reply-files-{:04}", self.next_sequence));
        std::fs::create_dir_all(&dir)?;
        self.dirs.push_back(dir.clone());
        while self.dirs.len() > retention_max_dirs {
            if let Some(path) = self.dirs.pop_front() {
                let _ = std::fs::remove_dir_all(path);
            }
        }
        Ok(dir)
    }
}

#[derive(Debug)]
pub(crate) struct ReplyPresentation {
    defaults: ReplyOverflowSettings,
    current: ReplyOverflowSettings,
    pager: Pager,
    pager_prompt: Option<String>,
    files: ReplyFilesManager,
}

impl ReplyPresentation {
    pub(crate) fn new(defaults: ReplyOverflowSettings) -> std::io::Result<Self> {
        Ok(Self {
            current: defaults.clone(),
            defaults,
            pager: Pager::default(),
            pager_prompt: None,
            files: ReplyFilesManager::new()?,
        })
    }

    pub(crate) fn update_settings(&mut self, latest: Option<ReplyOverflowSettings>) {
        if let Some(settings) = latest {
            self.current = settings;
            if self.current.behavior != ReplyOverflowBehavior::Pager {
                self.pager.dismiss();
                self.pager_prompt = None;
            }
        }
    }

    pub(crate) fn reset_to_defaults(&mut self) -> std::io::Result<()> {
        self.current = self.defaults.clone();
        self.pager.dismiss();
        self.pager_prompt = None;
        self.files.clear()
    }

    pub(crate) fn reset_settings_to_defaults(&mut self) {
        self.current = self.defaults.clone();
        self.pager.dismiss();
        self.pager_prompt = None;
    }

    pub(crate) fn handle_input_with_refresh<F>(
        &mut self,
        input: &str,
        refresh_pager: F,
    ) -> Option<WorkerReply>
    where
        F: FnOnce(&mut Pager),
    {
        if !self.pager.is_active() {
            return None;
        }
        if self.current.behavior != ReplyOverflowBehavior::Pager {
            self.pager.dismiss();
            self.pager_prompt = None;
            return None;
        }
        let trimmed = input.trim();
        if !trimmed.is_empty() && !trimmed.starts_with(':') {
            self.pager.dismiss();
            self.pager_prompt = None;
            return None;
        }

        refresh_pager(&mut self.pager);
        let mut reply = self.pager.handle_command(input);
        let pager_active = self.pager.is_active();
        let WorkerReply::Output {
            contents, prompt, ..
        } = &mut reply;
        let resolved_prompt = if pager_active {
            None
        } else {
            self.pager_prompt.take()
        };
        if pager_active {
            *prompt = None;
        } else {
            if resolved_prompt.is_none() {
                contents.push(WorkerContent::stderr(
                    "[repl] protocol error: missing prompt after pager dismiss",
                ));
            }
            append_prompt_if_missing(contents, resolved_prompt.clone());
            *prompt = resolved_prompt;
        }
        Some(reply)
    }

    pub(crate) fn present_reply_with_source_end(
        &mut self,
        reply: WorkerReply,
        source_end: Option<u64>,
    ) -> WorkerReply {
        match self.current.behavior {
            ReplyOverflowBehavior::Files => {
                self.pager.dismiss();
                self.pager_prompt = None;
                self.files.apply_to_reply(reply, &self.current)
            }
            ReplyOverflowBehavior::Pager => self.apply_pager(reply, source_end),
        }
    }

    fn apply_pager(&mut self, reply: WorkerReply, source_end: Option<u64>) -> WorkerReply {
        let page_bytes = pager::resolve_page_bytes(None);
        match reply {
            WorkerReply::Output {
                mut contents,
                is_error,
                error_code,
                prompt,
                prompt_variants,
                text_overflow,
            } => {
                contents = collapse_image_updates(contents);
                let prompt = prompt.filter(|value| !value.is_empty());
                let mut pager_source = truncate_contents_for_pager(contents);
                if let Some(prompt_text) = prompt.as_deref() {
                    strip_trailing_prompt(&mut pager_source, prompt_text);
                }
                let original_images = pager_source
                    .iter()
                    .filter(|content| matches!(content, WorkerContent::ContentImage { .. }))
                    .cloned()
                    .collect::<Vec<_>>();
                let snapshot = pager::snapshot_page_from_contents_with_source_end(
                    pager_source,
                    page_bytes,
                    source_end,
                );
                let mut contents = snapshot.contents;
                ensure_paged_reply_includes_images(&mut contents, &original_images);
                if snapshot.pages_left > 0 {
                    pager::maybe_activate_and_append_footer(
                        &mut self.pager,
                        &mut contents,
                        snapshot.pages_left,
                        is_error,
                        snapshot.buffer,
                        snapshot.last_range,
                    );
                    self.pager_prompt = prompt;
                    WorkerReply::Output {
                        contents,
                        is_error,
                        error_code,
                        prompt: None,
                        prompt_variants,
                        text_overflow,
                    }
                } else {
                    append_prompt_if_missing(&mut contents, prompt.clone());
                    WorkerReply::Output {
                        contents,
                        is_error,
                        error_code,
                        prompt,
                        prompt_variants,
                        text_overflow,
                    }
                }
            }
        }
    }
}

fn render_files_reply_contents(
    files: &mut ReplyFilesManager,
    contents: Vec<WorkerContent>,
    prompt: Option<&str>,
    settings: &ReplyOverflowSettings,
    text_overflow: Option<&crate::worker_protocol::WorkerTextOverflow>,
) -> Vec<WorkerContent> {
    let contents = collapse_image_updates(contents);
    let (body_contents, prompt_chunk) = split_prompt_chunk(contents, prompt);
    let body_has_text = body_contents.iter().any(|content| match content {
        WorkerContent::ContentText { text, .. } => {
            !text.starts_with("<<console status:")
                && !text.starts_with("[repl]")
                && !text.starts_with("worker error:")
        }
        WorkerContent::ContentImage { .. } => false,
    });
    if let Some(text_overflow) = text_overflow
        && !body_has_text
    {
        return render_existing_text_overflow_contents(
            files,
            body_contents,
            prompt_chunk,
            settings,
            text_overflow,
        );
    }

    let text_spans = body_contents
        .iter()
        .filter_map(|content| match content {
            WorkerContent::ContentText { text, .. } => Some(text.as_str()),
            WorkerContent::ContentImage { .. } => None,
        })
        .collect::<Vec<_>>();
    let full_text = text_spans.concat();
    let images = body_contents
        .iter()
        .filter(|content| matches!(content, WorkerContent::ContentImage { .. }))
        .cloned()
        .collect::<Vec<_>>();

    let text_budget = usize::try_from(settings.text.preview_bytes).unwrap_or(usize::MAX);
    let text_spills =
        full_text.len() > usize::try_from(settings.text.spill_bytes).unwrap_or(usize::MAX);
    let image_spills = images.len() > settings.images.spill_count;

    if !text_spills && !image_spills {
        return reattach_prompt(body_contents, prompt_chunk);
    }

    let inline_image_limit = if image_spills {
        settings.images.preview_count.min(images.len())
    } else {
        images.len()
    };

    let mut rendered = Vec::new();
    if text_spills {
        let preview = build_text_preview(&full_text, text_budget);
        if !preview.text.is_empty() {
            rendered.push(WorkerContent::stdout(preview.text.clone()));
        }
        for image in images.iter().take(inline_image_limit) {
            rendered.push(image.clone());
        }
        let mut annotations = write_reply_files(
            files,
            Some(&full_text),
            image_spills.then(|| {
                images
                    .iter()
                    .skip(inline_image_limit)
                    .cloned()
                    .collect::<Vec<_>>()
            }),
            Some(TextPreviewSummary {
                total_lines: preview.total_lines,
            }),
            inline_image_limit,
            images.len(),
            settings.retention.max_dirs,
        );
        if !preview.text.is_empty() && !annotations.is_empty() {
            if preview.text.ends_with('\n') || preview.text.ends_with('\r') {
                annotations.insert(0, '\n');
            } else {
                annotations.insert_str(0, "\n\n");
            }
        }
        if !annotations.is_empty() {
            rendered.push(WorkerContent::stderr(annotations));
        }
    } else {
        let mut seen_images = 0usize;
        for content in body_contents {
            match content {
                WorkerContent::ContentText { .. } => rendered.push(content),
                WorkerContent::ContentImage { .. } => {
                    if seen_images < inline_image_limit {
                        rendered.push(content);
                    }
                    seen_images = seen_images.saturating_add(1);
                }
            }
        }
        let annotations = write_reply_files(
            files,
            None,
            image_spills.then(|| {
                images
                    .iter()
                    .skip(inline_image_limit)
                    .cloned()
                    .collect::<Vec<_>>()
            }),
            None,
            inline_image_limit,
            images.len(),
            settings.retention.max_dirs,
        );
        if !annotations.is_empty() {
            rendered.push(WorkerContent::stderr(annotations));
        }
    }

    reattach_prompt(rendered, prompt_chunk)
}

fn render_existing_text_overflow_contents(
    files: &mut ReplyFilesManager,
    body_contents: Vec<WorkerContent>,
    prompt_chunk: Option<WorkerContent>,
    settings: &ReplyOverflowSettings,
    text_overflow: &crate::worker_protocol::WorkerTextOverflow,
) -> Vec<WorkerContent> {
    let images = body_contents
        .iter()
        .filter(|content| matches!(content, WorkerContent::ContentImage { .. }))
        .cloned()
        .collect::<Vec<_>>();
    let inline_image_limit = if images.len() > settings.images.spill_count {
        settings.images.preview_count.min(images.len())
    } else {
        images.len()
    };

    let saved_files = write_reply_files_from_existing_text(
        files,
        Path::new(&text_overflow.path),
        TextPreviewSummary {
            total_lines: text_overflow.total_lines,
        },
        (images.len() > inline_image_limit).then(|| {
            images
                .iter()
                .skip(inline_image_limit)
                .cloned()
                .collect::<Vec<_>>()
        }),
        inline_image_limit,
        images.len(),
        settings.retention.max_dirs,
    );
    let preview_path = saved_files
        .text_path
        .as_deref()
        .unwrap_or_else(|| Path::new(&text_overflow.path));

    let mut rendered = Vec::new();
    let preview = read_text_preview_from_path(
        preview_path,
        usize::try_from(settings.text.preview_bytes).unwrap_or(usize::MAX),
        text_overflow.total_chars,
    );
    let preview_ends_with_newline = preview.ends_with('\n') || preview.ends_with('\r');
    if !preview.is_empty() {
        rendered.push(WorkerContent::stdout(preview.clone()));
    }

    let mut seen_images = 0usize;
    for content in body_contents {
        match content {
            WorkerContent::ContentText { .. } => rendered.push(content),
            WorkerContent::ContentImage { .. } => {
                if seen_images < inline_image_limit {
                    rendered.push(content);
                }
                seen_images = seen_images.saturating_add(1);
            }
        }
    }

    let annotations = saved_files.annotation.trim_end_matches('\n').to_string();

    if !annotations.is_empty() {
        if !preview.is_empty() {
            if preview_ends_with_newline {
                rendered.push(WorkerContent::stderr(format!("\n{annotations}\n")));
            } else {
                rendered.push(WorkerContent::stderr(format!("\n\n{annotations}\n")));
            }
        } else {
            rendered.push(WorkerContent::stderr(format!("{annotations}\n")));
        }
    }

    reattach_prompt(rendered, prompt_chunk)
}

fn collapse_image_updates(contents: Vec<WorkerContent>) -> Vec<WorkerContent> {
    let mut group_for_index: Vec<Option<usize>> = vec![None; contents.len()];
    let mut last_in_group: Vec<usize> = Vec::new();
    let mut current_group: Option<usize> = None;

    for (idx, content) in contents.iter().enumerate() {
        if let WorkerContent::ContentImage { is_new, .. } = content {
            if *is_new || current_group.is_none() {
                current_group = Some(last_in_group.len());
                last_in_group.push(idx);
            }
            let group = current_group.expect("image group should be set");
            group_for_index[idx] = Some(group);
            last_in_group[group] = idx;
        }
    }

    contents
        .into_iter()
        .enumerate()
        .filter_map(|(idx, content)| match &content {
            WorkerContent::ContentImage { .. } => match group_for_index[idx] {
                Some(group) if last_in_group.get(group).copied() == Some(idx) => Some(content),
                _ => None,
            },
            _ => Some(content),
        })
        .collect()
}

fn split_prompt_chunk(
    mut contents: Vec<WorkerContent>,
    prompt: Option<&str>,
) -> (Vec<WorkerContent>, Option<WorkerContent>) {
    let Some(prompt) = prompt else {
        return (contents, None);
    };
    let Some(WorkerContent::ContentText {
        text,
        stream: TextStream::Stdout,
    }) = contents.last()
    else {
        return (contents, None);
    };
    if text != prompt {
        return (contents, None);
    }
    let prompt_chunk = contents.pop();
    (contents, prompt_chunk)
}

fn reattach_prompt(
    mut contents: Vec<WorkerContent>,
    prompt_chunk: Option<WorkerContent>,
) -> Vec<WorkerContent> {
    if let Some(prompt_chunk) = prompt_chunk {
        contents.push(prompt_chunk);
    }
    contents
}

fn truncate_contents_for_pager(contents: Vec<WorkerContent>) -> Vec<WorkerContent> {
    let total_text_bytes = contents
        .iter()
        .filter_map(|content| match content {
            WorkerContent::ContentText { text, .. } => Some(text.len()),
            WorkerContent::ContentImage { .. } => None,
        })
        .sum::<usize>();
    if total_text_bytes <= OUTPUT_RING_CAPACITY_BYTES {
        return contents;
    }

    let mut kept_rev = Vec::new();
    let mut remaining = OUTPUT_RING_CAPACITY_BYTES;
    for content in contents.into_iter().rev() {
        match content {
            WorkerContent::ContentText { text, stream } => {
                if remaining == 0 {
                    continue;
                }
                if text.len() <= remaining {
                    remaining = remaining.saturating_sub(text.len());
                    kept_rev.push(WorkerContent::ContentText { text, stream });
                } else {
                    kept_rev.push(WorkerContent::ContentText {
                        text: take_suffix_chars(&text, remaining),
                        stream,
                    });
                    remaining = 0;
                }
            }
            WorkerContent::ContentImage { .. } => kept_rev.push(content),
        }
    }
    kept_rev.reverse();
    let mut out = vec![WorkerContent::stdout(
        "[repl] output truncated (older output dropped)\n",
    )];
    out.extend(kept_rev);
    out
}

fn ensure_paged_reply_includes_images(
    contents: &mut Vec<WorkerContent>,
    original_images: &[WorkerContent],
) {
    if contents
        .iter()
        .any(|content| matches!(content, WorkerContent::ContentImage { .. }))
        || original_images.is_empty()
    {
        return;
    }
    let count = pager::MAX_IMAGES_PER_PAGE.min(original_images.len());
    contents.extend(
        original_images[original_images.len().saturating_sub(count)..]
            .iter()
            .cloned(),
    );
}

fn take_suffix_chars(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut start = text.len().saturating_sub(max_bytes);
    while start < text.len() && !text.is_char_boundary(start) {
        start = start.saturating_add(1);
    }
    text[start..].to_string()
}

fn append_prompt_if_missing(contents: &mut Vec<WorkerContent>, prompt: Option<String>) {
    let Some(prompt) = prompt else {
        return;
    };
    if prompt.is_empty() {
        return;
    }
    if let Some(WorkerContent::ContentText { text, .. }) = contents
        .iter()
        .rev()
        .find(|content| matches!(content, WorkerContent::ContentText { .. }))
        && text.ends_with(&prompt)
    {
        return;
    }
    contents.push(WorkerContent::stdout(prompt));
}

fn strip_trailing_prompt(contents: &mut Vec<WorkerContent>, prompt: &str) {
    if prompt.is_empty() {
        return;
    }
    let idx = contents
        .iter()
        .rposition(|content| matches!(content, WorkerContent::ContentText { .. }));
    let Some(idx) = idx else {
        return;
    };
    let WorkerContent::ContentText { text, stream } = &contents[idx] else {
        return;
    };
    let Some(prefix) = text.strip_suffix(prompt) else {
        return;
    };
    if prefix.is_empty() {
        contents.remove(idx);
    } else {
        contents[idx] = WorkerContent::ContentText {
            text: prefix.to_string(),
            stream: *stream,
        };
    }
}

struct TextPreview {
    text: String,
    total_lines: usize,
}

#[derive(Clone, Copy)]
struct TextPreviewSummary {
    total_lines: usize,
}

struct SavedReplyFiles {
    annotation: String,
    text_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SavedImageRange {
    extension: String,
    start_index: usize,
    end_index: usize,
}

fn write_reply_files(
    files: &mut ReplyFilesManager,
    full_text: Option<&str>,
    omitted_images: Option<Vec<WorkerContent>>,
    text_preview: Option<TextPreviewSummary>,
    inline_images: usize,
    total_images: usize,
    retention_max_dirs: usize,
) -> String {
    let need_text = full_text.is_some();
    let need_images = omitted_images
        .as_ref()
        .is_some_and(|images| !images.is_empty());
    if !need_text && !need_images {
        return String::new();
    }

    let dir = match files.next_reply_dir(retention_max_dirs) {
        Ok(path) => path,
        Err(err) => return format!("[repl] failed to write reply files: {err}\n"),
    };

    let mut lines = Vec::new();

    if let Some(text) = full_text {
        let text_path = dir.join("output.log");
        match std::fs::write(&text_path, text) {
            Ok(()) => {
                let summary =
                    text_preview.expect("text preview should be present when text spills");
                lines.push(format!(
                    "[full output ({} {}) written to {}]",
                    summary.total_lines,
                    pluralize(summary.total_lines, "line", "lines"),
                    text_path.display()
                ));
            }
            Err(err) => lines.push(format!(
                "[repl] failed to write full text file {}: {err}]",
                text_path.display()
            )),
        }
    }

    lines.extend(write_omitted_images(
        &dir,
        omitted_images,
        inline_images,
        total_images,
    ));

    format_annotation_lines(lines)
}

fn write_reply_files_from_existing_text(
    files: &mut ReplyFilesManager,
    source_path: &Path,
    text_preview: TextPreviewSummary,
    omitted_images: Option<Vec<WorkerContent>>,
    inline_images: usize,
    total_images: usize,
    retention_max_dirs: usize,
) -> SavedReplyFiles {
    let need_text = true;
    let need_images = omitted_images
        .as_ref()
        .is_some_and(|images| !images.is_empty());
    if !need_text && !need_images {
        return SavedReplyFiles {
            annotation: String::new(),
            text_path: None,
        };
    }

    let dir = match files.next_reply_dir(retention_max_dirs) {
        Ok(path) => path,
        Err(err) => {
            return SavedReplyFiles {
                annotation: format!("[repl] failed to write reply files: {err}\n"),
                text_path: None,
            };
        }
    };

    let mut lines = Vec::new();
    let mut text_path = None;
    if need_text {
        let copied_path = dir.join("output.log");
        match std::fs::copy(source_path, &copied_path) {
            Ok(_) => {
                lines.push(format!(
                    "[full output ({} {}) written to {}]",
                    text_preview.total_lines,
                    pluralize(text_preview.total_lines, "line", "lines"),
                    copied_path.display()
                ));
                text_path = Some(copied_path);
            }
            Err(err) => lines.push(format!(
                "[repl] failed to copy full text file {}: {err}]",
                source_path.display()
            )),
        }
    }

    lines.extend(write_omitted_images(
        &dir,
        omitted_images,
        inline_images,
        total_images,
    ));

    SavedReplyFiles {
        annotation: format_annotation_lines(lines),
        text_path,
    }
}

fn write_omitted_images(
    dir: &Path,
    omitted_images: Option<Vec<WorkerContent>>,
    inline_images: usize,
    total_images: usize,
) -> Vec<String> {
    let mut lines = Vec::new();

    if let Some(images) = omitted_images
        && !images.is_empty()
    {
        lines.push(format!(
            "[inline images={}, saved images={}]",
            inline_images,
            total_images.saturating_sub(inline_images)
        ));
        let mut saved_ranges = Vec::new();
        for (idx, image) in images.into_iter().enumerate() {
            let WorkerContent::ContentImage {
                data, mime_type, ..
            } = image
            else {
                continue;
            };
            let extension = image_extension(&mime_type);
            let path = dir.join(format!("image-{:04}.{}", idx + 1, extension));
            match base64::engine::general_purpose::STANDARD.decode(data.as_bytes()) {
                Ok(bytes) => match std::fs::write(&path, bytes) {
                    Ok(()) => push_saved_image_range(&mut saved_ranges, idx + 1, extension),
                    Err(err) => lines.push(format!(
                        "[repl] failed to write image file {}: {err}]",
                        path.display()
                    )),
                },
                Err(err) => lines.push(format!(
                    "[repl] failed to decode image for {}: {err}]",
                    path.display()
                )),
            }
        }
        for range in saved_ranges {
            lines.push(format_saved_image_range_line(dir, &range));
        }
    }

    lines
}

fn format_annotation_lines(lines: Vec<String>) -> String {
    if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    }
}

fn build_reply_files_root() -> std::io::Result<PathBuf> {
    let parent = std::env::temp_dir();
    for _ in 0..128 {
        let sequence = REPLY_FILES_ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            "mcp-repl-reply-files-{}-{}",
            std::process::id(),
            sequence
        ));
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "failed to allocate reply files root",
    ))
}

fn build_text_preview(text: &str, preview_bytes: usize) -> TextPreview {
    let total_chars = text.chars().count();
    let total_lines = count_text_lines(text);
    if preview_bytes == 0 {
        return TextPreview {
            text: String::new(),
            total_lines,
        };
    }
    let mut preview = take_prefix_chars(text, preview_bytes);
    if total_chars > preview.chars().count() {
        while preview.ends_with('\n') || preview.ends_with('\r') {
            preview.pop();
        }
        preview.push_str(&format!("...[truncated, total {total_chars} chars]"));
    }
    TextPreview {
        text: preview,
        total_lines,
    }
}

fn read_text_preview_from_path(path: &Path, preview_bytes: usize, total_chars: usize) -> String {
    if preview_bytes == 0 {
        return String::new();
    }
    let Ok(mut file) = std::fs::File::open(path) else {
        return String::new();
    };
    let mut bytes = Vec::with_capacity(preview_bytes.saturating_add(4));
    if std::io::Read::by_ref(&mut file)
        .take(preview_bytes.saturating_add(4) as u64)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return String::new();
    }
    let mut preview = take_prefix_chars(&String::from_utf8_lossy(&bytes), preview_bytes);
    if total_chars > preview.chars().count() {
        while preview.ends_with('\n') || preview.ends_with('\r') {
            preview.pop();
        }
        preview.push_str(&format!("...[truncated, total {total_chars} chars]"));
    }
    preview
}

fn count_text_lines(text: &str) -> usize {
    if text.is_empty() {
        return 0;
    }
    let newline_count = text.bytes().filter(|byte| *byte == b'\n').count();
    if text.ends_with('\n') {
        newline_count
    } else {
        newline_count.saturating_add(1)
    }
}

fn pluralize<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

fn push_saved_image_range(ranges: &mut Vec<SavedImageRange>, index: usize, extension: &str) {
    if let Some(last) = ranges.last_mut()
        && last.extension == extension
        && last.end_index.saturating_add(1) == index
    {
        last.end_index = index;
        return;
    }
    ranges.push(SavedImageRange {
        extension: extension.to_string(),
        start_index: index,
        end_index: index,
    });
}

fn format_saved_image_range_line(dir: &Path, range: &SavedImageRange) -> String {
    let pattern = dir.join(format!("image-NNNN.{}", range.extension));
    let numbers = if range.start_index == range.end_index {
        format!("{:04}", range.start_index)
    } else {
        format!("{:04}..{:04}", range.start_index, range.end_index)
    };
    format!(
        "[saved images: {} where NNNN={}]",
        pattern.display(),
        numbers
    )
}

fn take_prefix_chars(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut out = String::new();
    for (idx, ch) in text.char_indices() {
        if idx >= max_bytes {
            break;
        }
        out.push(ch);
    }
    out
}

fn image_extension(mime_type: &str) -> &'static str {
    match mime_type.trim().to_ascii_lowercase().as_str() {
        "image/png" => "png",
        "image/jpeg" | "image/jpg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        _ => "bin",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_preview_caps_large_multiline_output() {
        let text = format!("{}\nOK\n", "x".repeat(8_192));
        let preview = build_text_preview(&text, 64);
        assert!(preview.text.len() < 256, "preview was too large");
        assert!(preview.text.contains("[truncated, total 8196 chars]"));
        assert_eq!(preview.total_lines, 2);
    }

    #[test]
    fn zero_byte_preview_shows_only_file_annotation_summary() {
        let preview = build_text_preview("abcdef", 0);
        assert!(preview.text.is_empty());
        assert_eq!(preview.total_lines, 1);
    }

    #[test]
    fn count_text_lines_handles_trailing_newline() {
        assert_eq!(count_text_lines(""), 0);
        assert_eq!(count_text_lines("abc"), 1);
        assert_eq!(count_text_lines("abc\n"), 1);
        assert_eq!(count_text_lines("a\nb\n"), 2);
    }

    #[test]
    fn saved_image_ranges_are_reported_compactly() {
        let mut ranges = Vec::new();
        push_saved_image_range(&mut ranges, 1, "png");
        push_saved_image_range(&mut ranges, 2, "png");
        push_saved_image_range(&mut ranges, 4, "png");
        push_saved_image_range(&mut ranges, 5, "jpg");

        assert_eq!(
            ranges,
            vec![
                SavedImageRange {
                    extension: "png".to_string(),
                    start_index: 1,
                    end_index: 2,
                },
                SavedImageRange {
                    extension: "png".to_string(),
                    start_index: 4,
                    end_index: 4,
                },
                SavedImageRange {
                    extension: "jpg".to_string(),
                    start_index: 5,
                    end_index: 5,
                },
            ]
        );

        let dir = Path::new("/tmp/reply-files-0001");
        assert_eq!(
            format_saved_image_range_line(dir, &ranges[0]),
            "[saved images: /tmp/reply-files-0001/image-NNNN.png where NNNN=0001..0002]"
        );
    }

    #[test]
    fn retains_prompt_after_spilling_text() {
        let mut files = ReplyFilesManager::new().expect("manager");
        let settings = ReplyOverflowSettings::default();
        let reply = WorkerReply::Output {
            contents: vec![
                WorkerContent::stdout("x".repeat(4_000)),
                WorkerContent::stdout("> "),
            ],
            is_error: false,
            error_code: None,
            prompt: Some("> ".to_string()),
            prompt_variants: None,
            text_overflow: None,
        };

        let WorkerReply::Output { contents, .. } = files.apply_to_reply(reply, &settings);
        assert!(
            matches!(contents.last(), Some(WorkerContent::ContentText { text, .. }) if text == "> ")
        );
        let rendered = contents
            .into_iter()
            .filter_map(|content| match content {
                WorkerContent::ContentText { text, .. } => Some(text),
                WorkerContent::ContentImage { .. } => None,
            })
            .collect::<Vec<_>>()
            .join("");
        assert!(rendered.contains("[full output (1 line) written to "));
    }
}
