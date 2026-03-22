use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use rmcp::model::{AnnotateAble, CallToolResult, Content, Meta, RawContent, RawImageContent};
use serde_json::json;
use tempfile::Builder;

use crate::worker_process::WorkerError;
use crate::worker_protocol::{ContentOrigin, WorkerContent, WorkerErrorCode, WorkerReply};

const INLINE_TEXT_BUDGET: usize = 3500;

pub(crate) struct ResponseState {
    transcripts: TranscriptStore,
    active_timeout_transcript: Option<ActiveTranscript>,
}

struct TranscriptStore {
    root: tempfile::TempDir,
    next_id: u64,
}

#[derive(Clone)]
struct ActiveTranscript {
    path: PathBuf,
}

enum RenderedItem {
    WorkerText(String),
    ServerText(String),
    Image(Box<Content>),
}

struct ReplyMaterial {
    items: Vec<RenderedItem>,
    worker_text: String,
    is_error: bool,
    error_code: Option<WorkerErrorCode>,
    contains_image: bool,
}

impl ResponseState {
    pub(crate) fn new() -> Result<Self, WorkerError> {
        Ok(Self {
            transcripts: TranscriptStore::new()?,
            active_timeout_transcript: None,
        })
    }

    /// Converts a worker result into the final MCP reply, including transcript updates and
    /// oversized-text compaction.
    pub(crate) fn finalize_worker_result(
        &mut self,
        result: Result<WorkerReply, WorkerError>,
        pending_request_after: bool,
    ) -> CallToolResult {
        match result {
            Ok(reply) => self.finalize_reply(reply, pending_request_after),
            Err(err) => {
                eprintln!("worker write stdin error: {err}");
                finalize_batch(vec![Content::text(format!("worker error: {err}"))], true)
            }
        }
    }

    /// Splits worker-originated text from server-only notices, keeps timeout polls on one
    /// transcript path, and only discloses that path once text actually needs compaction.
    fn finalize_reply(
        &mut self,
        reply: WorkerReply,
        pending_request_after: bool,
    ) -> CallToolResult {
        let material = prepare_reply_material(reply);

        if material.error_code == Some(WorkerErrorCode::Timeout)
            && self.active_timeout_transcript.is_none()
        {
            let path = self
                .transcripts
                .new_transcript_path()
                .expect("failed to create timeout transcript path");
            self.active_timeout_transcript = Some(ActiveTranscript { path });
        }

        if !material.worker_text.is_empty()
            && let Some(active) = self.active_timeout_transcript.as_ref()
        {
            self.transcripts
                .append(&active.path, &material.worker_text)
                .expect("failed to append timeout transcript");
        }

        let contents = if material.contains_image {
            materialize_items(material.items)
        } else if material.worker_text.chars().count() > INLINE_TEXT_BUDGET {
            let path = match self.active_timeout_transcript.as_ref() {
                Some(active) => active.path.clone(),
                None => {
                    let path = self
                        .transcripts
                        .new_transcript_path()
                        .expect("failed to create transcript path");
                    self.transcripts
                        .append(&path, &material.worker_text)
                        .expect("failed to append transcript");
                    path
                }
            };
            compact_items(material.items, &material.worker_text, &path)
        } else {
            materialize_items(material.items)
        };

        if !pending_request_after {
            self.active_timeout_transcript = None;
        }

        finalize_batch(contents, material.is_error)
    }
}

impl TranscriptStore {
    fn new() -> Result<Self, WorkerError> {
        let root = Builder::new()
            .prefix("mcp-repl-spill-")
            .tempdir()
            .map_err(WorkerError::Io)?;
        Ok(Self { root, next_id: 0 })
    }

    /// Allocates a stable absolute path for the next spill file under the server-owned temp root.
    fn new_transcript_path(&mut self) -> Result<PathBuf, WorkerError> {
        self.next_id = self.next_id.saturating_add(1);
        let path = self
            .root
            .path()
            .join(format!("spill-{:04}.txt", self.next_id));
        std::fs::File::create(&path).map_err(WorkerError::Io)?;
        Ok(path)
    }

    /// Appends worker-originated text exactly as surfaced to the client, without server-only
    /// status markers such as timeout notices.
    fn append(&self, path: &Path, text: &str) -> Result<(), WorkerError> {
        if text.is_empty() {
            return Ok(());
        }
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .map_err(WorkerError::Io)?;
        file.write_all(text.as_bytes()).map_err(WorkerError::Io)?;
        Ok(())
    }
}

/// Normalizes one worker reply into renderable items while preserving the split between
/// worker-originated transcript text and inline-only server notices.
fn prepare_reply_material(reply: WorkerReply) -> ReplyMaterial {
    let (contents, is_error, error_code) = match reply {
        WorkerReply::Output {
            contents,
            is_error,
            error_code,
            prompt: _,
            prompt_variants: _,
        } => (contents, is_error, error_code),
    };

    let contents = collapse_image_updates(contents);
    let mut items = Vec::with_capacity(contents.len());
    let mut worker_text = String::new();
    let mut contains_image = false;

    for content in contents {
        match content {
            WorkerContent::ContentText { text, origin, .. } => {
                let text = if matches!(origin, ContentOrigin::Worker) {
                    normalize_error_prompt(text, is_error)
                } else {
                    text
                };
                if text.is_empty() {
                    continue;
                }
                match origin {
                    ContentOrigin::Worker => {
                        worker_text.push_str(&text);
                        items.push(RenderedItem::WorkerText(text));
                    }
                    ContentOrigin::Server => items.push(RenderedItem::ServerText(text)),
                }
            }
            WorkerContent::ContentImage {
                data,
                mime_type,
                id,
                is_new,
            } => {
                contains_image = true;
                items.push(RenderedItem::Image(Box::new(content_image_with_meta(
                    data, mime_type, id, is_new,
                ))));
            }
        }
    }

    ReplyMaterial {
        items,
        worker_text,
        is_error,
        error_code,
        contains_image,
    }
}

pub(crate) fn finalize_batch(mut contents: Vec<Content>, is_error: bool) -> CallToolResult {
    ensure_nonempty_contents(&mut contents);
    let _ = is_error;
    CallToolResult::success(contents)
}

fn materialize_items(items: Vec<RenderedItem>) -> Vec<Content> {
    items
        .into_iter()
        .map(|item| match item {
            RenderedItem::WorkerText(text) | RenderedItem::ServerText(text) => Content::text(text),
            RenderedItem::Image(content) => *content,
        })
        .collect()
}

fn compact_items(items: Vec<RenderedItem>, worker_text: &str, path: &Path) -> Vec<Content> {
    let preview = build_preview(worker_text, path);
    let mut out = Vec::new();
    let mut worker_inserted = false;
    for item in items {
        match item {
            RenderedItem::WorkerText(_) => {
                if !worker_inserted {
                    out.push(Content::text(preview.clone()));
                    worker_inserted = true;
                }
            }
            RenderedItem::ServerText(text) => out.push(Content::text(text)),
            RenderedItem::Image(content) => out.push(*content),
        }
    }
    out
}

fn build_preview(text: &str, path: &Path) -> String {
    if let Some(preview) = build_line_preview(text, path) {
        return preview;
    }
    build_char_preview(text, path)
}

fn build_line_preview(text: &str, path: &Path) -> Option<String> {
    if !text.contains('\n') {
        return None;
    }
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    if lines.len() < 3 {
        return None;
    }

    let head_budget = INLINE_TEXT_BUDGET * 2 / 3;
    let tail_budget = INLINE_TEXT_BUDGET / 3;

    let mut head_count = 0usize;
    let mut head_len = 0usize;
    while head_count < lines.len() {
        let next = head_len + lines[head_count].chars().count();
        if next > head_budget && head_count > 0 {
            break;
        }
        head_len = next;
        head_count += 1;
    }

    let mut tail_count = 0usize;
    let mut tail_len = 0usize;
    while tail_count < lines.len().saturating_sub(head_count) {
        let line = lines[lines.len() - 1 - tail_count];
        let next = tail_len + line.chars().count();
        if next > tail_budget && tail_count > 0 {
            break;
        }
        tail_len = next;
        tail_count += 1;
    }

    if head_count + tail_count >= lines.len() || head_count == 0 || tail_count == 0 {
        return None;
    }

    let head = lines[..head_count].concat();
    let tail = lines[lines.len() - tail_count..].concat();
    let marker = format!(
        "...[middle truncated; shown lines 1-{head_count} and {}-{} of {} total; full output: {}]...",
        lines.len() - tail_count + 1,
        lines.len(),
        lines.len(),
        path.display()
    );

    Some(format!("{head}{marker}\n{tail}"))
}

fn build_char_preview(text: &str, path: &Path) -> String {
    let chars: Vec<char> = text.chars().collect();
    let total = chars.len();
    let head_chars = INLINE_TEXT_BUDGET * 2 / 3;
    let tail_chars = INLINE_TEXT_BUDGET / 3;
    let head_end = head_chars.min(total);
    let tail_start = total.saturating_sub(tail_chars);
    let head: String = chars[..head_end].iter().collect();
    let tail: String = chars[tail_start..].iter().collect();
    let marker = format!(
        "...[middle truncated; shown chars 1-{head_end} and {}-{} of {} total; full output: {}]...",
        tail_start.saturating_add(1),
        total,
        total,
        path.display()
    );
    format!("{head}\n{marker}\n{tail}")
}

fn ensure_nonempty_contents(contents: &mut Vec<Content>) {
    if contents.is_empty() {
        contents.push(Content::text(String::new()));
    }
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

fn normalize_error_prompt(text: String, is_error: bool) -> String {
    if !is_error {
        return text;
    }
    let mut normalized = String::with_capacity(text.len());
    let mut normalized_any = false;
    for line in text.split_inclusive('\n') {
        if let Some(rest) = line.strip_prefix("> ")
            && rest.starts_with("Error")
        {
            normalized.push_str(rest);
            normalized_any = true;
        } else {
            normalized.push_str(line);
        }
    }

    if normalized_any && !normalized.ends_with("\n> ") && !normalized.ends_with("> ") {
        if !normalized.ends_with('\n') {
            normalized.push('\n');
        }
        normalized.push_str("> ");
    }

    if normalized_any { normalized } else { text }
}

fn content_image_with_meta(data: String, mime_type: String, id: String, is_new: bool) -> Content {
    let mut meta = Meta::new();
    let image_id = normalize_plot_id(&id);
    meta.0.insert(
        "mcpConsole".to_string(),
        json!({
            "imageId": image_id,
            "isNewPage": is_new,
        }),
    );
    RawContent::Image(RawImageContent {
        data,
        mime_type,
        meta: Some(meta),
    })
    .no_annotation()
}

fn normalize_plot_id(raw: &str) -> String {
    let Some(rest) = raw.strip_prefix("plot-") else {
        return raw.to_string();
    };
    let mut parts = rest.splitn(2, '-');
    let _pid = parts.next();
    let Some(counter) = parts.next() else {
        return raw.to_string();
    };
    if counter.chars().all(|ch| ch.is_ascii_digit()) {
        format!("plot-{counter}")
    } else {
        raw.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_error_prompt;

    #[test]
    fn compact_search_cards_do_not_trigger_error_prompt_normalization() {
        let text = "[pager] search for `Error` @10\n[match] Error: boom\n".to_string();
        assert_eq!(normalize_error_prompt(text.clone(), true), text);
    }
}
