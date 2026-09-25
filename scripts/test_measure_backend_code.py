import unittest

from measure_backend_code import line_kinds, mask_rust, rust_structure, test_item_spans


class RustLineCountTests(unittest.TestCase):
    def test_comments_and_blank_lines_are_separate_from_code(self):
        source = '''//! docs
fn example() { // inline note
    /* block
       with a blank line
    */
    let value = r#"// not a comment
/* nor a block */"#;
    let quote = '\\'';
}
'''
        code, comments, blank = line_kinds(source)
        self.assertEqual((code, comments, blank), (5, 4, 0))

    def test_cfg_test_items_are_removed_from_production_counts(self):
        source = '''fn kept() {}
#[cfg(test)]
mod tests {
    #[test]
    fn only_test() { let brace = "}"; }
}
'''
        spans = test_item_spans(source)
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0][:2], (1, 6))
        self.assertEqual(line_kinds(source)[0], 6)
        self.assertEqual(rust_structure(source, spans), (1, 0))

    def test_feature_gated_test_attribute_remains_visible(self):
        source = '''#[cfg(all(test, feature = "backend-hudsucker"))]
fn gated_test() {}
'''
        spans = test_item_spans(source)
        self.assertEqual(len(spans), 1)
        self.assertIn("backend-hudsucker", spans[0][2])

    def test_empty_lines_inside_raw_strings_are_literal_code(self):
        self.assertEqual(line_kinds('let body = r#"\n\n"#;\n'), (3, 0, 0))


if __name__ == "__main__":
    unittest.main()
