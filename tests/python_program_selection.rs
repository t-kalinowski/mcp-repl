mod common;

#[test]
fn python_program_prefers_python3_when_both_interpreters_work() {
    let selected =
        common::python_program_with_checker(|program| matches!(program, "python" | "python3"));
    assert_eq!(selected, Some("python3"));
}

#[test]
fn python_program_falls_back_to_python_when_python3_missing() {
    let selected = common::python_program_with_checker(|program| program == "python");
    assert_eq!(selected, Some("python"));
}

#[test]
fn python_program_returns_none_when_no_interpreter_works() {
    let selected = common::python_program_with_checker(|_| false);
    assert_eq!(selected, None);
}
