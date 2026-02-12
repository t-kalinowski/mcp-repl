use crate::output_capture::OutputEventKind;
use crate::worker_protocol::WorkerContent;

pub(crate) trait EventView {
    fn offset(&self) -> u64;
    fn kind(&self) -> &OutputEventKind;
}

pub(crate) fn merge_bytes_with_events<E: EventView>(
    bytes: &[u8],
    base_offset: u64,
    end_offset: u64,
    events: &[E],
    event_to_content: impl Fn(&OutputEventKind) -> WorkerContent,
) -> Vec<WorkerContent> {
    let mut contents = Vec::new();
    let mut cursor = 0usize;
    for event in events
        .iter()
        .filter(|event| event.offset() >= base_offset && event.offset() <= end_offset)
    {
        let relative = event.offset().saturating_sub(base_offset) as usize;
        if relative > bytes.len() {
            break;
        }
        if relative > cursor {
            let text = String::from_utf8_lossy(&bytes[cursor..relative]).into_owned();
            if !text.is_empty() {
                contents.push(WorkerContent::stdout(text));
            }
        }
        contents.push(event_to_content(event.kind()));
        cursor = relative;
    }
    if cursor < bytes.len() {
        let text = String::from_utf8_lossy(&bytes[cursor..]).into_owned();
        if !text.is_empty() {
            contents.push(WorkerContent::stdout(text));
        }
    }
    contents
}
