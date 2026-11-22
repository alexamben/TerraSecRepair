# -*- coding: utf-8 -*-
"""Regression tests for the patch validator's suppression guard and
parse-based resource preservation (review 2, comment 1).

Run: python -m unittest tests.test_validator -v
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from iac_lib.validate import has_suppression, resource_addresses, resources_preserved

ORIGINAL = '''
resource "aws_s3_bucket" "data" {
  bucket = "docs"
}
resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
}
'''

VALID_PATCH = '''
resource "aws_s3_bucket" "data" {
  bucket = "docs"
}
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
'''

SKIP_PATCH = VALID_PATCH + '''
# checkov:skip=CKV_AWS_18:not needed
'''

COMMENTED_OUT_PATCH = '''
resource "aws_s3_bucket" "data" {
  bucket = "docs"
}
# resource "aws_s3_bucket_public_access_block" "data" {
#   bucket = aws_s3_bucket.data.id
#   block_public_acls = true
# }
'''


class TestSuppressionGuard(unittest.TestCase):
    def test_skip_comment_detected(self):
        self.assertTrue(has_suppression(SKIP_PATCH))

    def test_trivy_ignore_detected(self):
        self.assertTrue(has_suppression("# trivy:ignore:CKV_AWS_20"))

    def test_clean_patch_not_flagged(self):
        self.assertFalse(has_suppression(VALID_PATCH))


class TestParseBasedPreservation(unittest.TestCase):
    def test_valid_patch_preserves_all(self):
        self.assertTrue(resources_preserved(ORIGINAL, VALID_PATCH))

    def test_commented_out_resource_is_not_preserved(self):
        # the regex-based check credited the commented declaration; the
        # parse tree does not, so commenting a resource out fails preservation
        self.assertFalse(resources_preserved(ORIGINAL, COMMENTED_OUT_PATCH))

    def test_resource_addresses_from_parse_tree(self):
        self.assertEqual(resource_addresses(ORIGINAL),
                         {("aws_s3_bucket", "data"),
                          ("aws_s3_bucket_public_access_block", "data")})

    def test_commented_declaration_not_in_parse_tree(self):
        self.assertEqual(resource_addresses(COMMENTED_OUT_PATCH),
                         {("aws_s3_bucket", "data")})

    def test_unparseable_patch_yields_no_addresses(self):
        self.assertEqual(resource_addresses("this is not hcl {{{"), set())


if __name__ == "__main__":
    unittest.main()
