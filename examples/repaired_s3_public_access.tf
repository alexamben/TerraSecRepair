resource "aws_s3_bucket_public_access_block" "api_docs" {
  bucket                  = aws_s3_bucket.api_docs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}