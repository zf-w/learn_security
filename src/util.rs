pub fn pop_newline_from_string_mut_ref(string_mut_ref: &mut String) {
    while string_mut_ref.ends_with('\n') {
        string_mut_ref.pop();
        if string_mut_ref.ends_with('\r') {
            string_mut_ref.pop();
        }
    }
}
