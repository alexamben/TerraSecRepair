resource "aws_s3_bucket_public_access_block" "api_docs" {
  bucket = aws_s3_bucket.api_docs.id
  restrict_public_buckets = false
}