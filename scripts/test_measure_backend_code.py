import unittest

from measure_backend_code import (
    ca_test_groups,
    feature_item_spans,
    line_kinds,
    mask_rust,
    rust_structure,
    test_item_spans,
)


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

    def test_feature_ownership_includes_a_complete_function_body(self):
        source = '''#[cfg(feature = "backend-hudsucker")]
fn hudsucker() {
    let value = (1, 2);
    assert_eq!(value.0, 1);
}
fn shared() {}
'''
        self.assertEqual(feature_item_spans(source, "backend-hudsucker"), [(0, 5)])

    def test_feature_ownership_stops_at_a_gated_struct_field(self):
        source = '''struct Ca {
    #[cfg(feature = "backend-rama")]
    rama_key: Key,
    shared: Vec<u8>,
}
'''
        self.assertEqual(feature_item_spans(source, "backend-rama"), [(1, 3)])

    def test_ca_test_split_counts_shared_validation_once(self):
        source = '''#[cfg(all(test, feature = "backend-hudsucker"))]
mod tests {
    use crate::config::CaConfig;
    fn ca_config() {}
    #[test]
    fn validates_ca_material_and_keeps_public_export_separate_from_the_key() {}
    #[tokio::test]
    async fn proxy_handles_one_shared_hudsucker_certificate_cache() {}
}
'''
        groups = ca_test_groups(source, test_item_spans(source))
        shared = groups["Shared CA validation unit tests (currently Hudsucker-gated)"]
        hudsucker = groups["Hudsucker-specific CA runtime unit tests"]
        self.assertGreater(shared[0], 0)
        self.assertGreater(hudsucker[0], 0)
        self.assertEqual(
            tuple(shared[index] + hudsucker[index] for index in range(3)),
            line_kinds(source),
        )


if __name__ == "__main__":
    unittest.main()
