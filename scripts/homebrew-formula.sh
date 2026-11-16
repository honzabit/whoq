#!/usr/bin/env bash
# Print the Homebrew formula for a release: scripts/homebrew-formula.sh v0.1.0 SHA256SUMS
set -euo pipefail
tag="$1"
sums="$2"
base="https://github.com/honzabit/whoq/releases/download/${tag}"

sha() {
  local file="whoq-${tag}-$1.tar.gz"
  local s
  s=$(awk -v f="$file" '$2 == f { print $1 }' "$sums")
  [ -n "$s" ] || { echo "no checksum for $file in $sums" >&2; exit 1; }
  echo "$s"
}

cat <<RUBY
class Whoq < Formula
  desc "RDAP-first WHOIS for humans and agents"
  homepage "https://github.com/honzabit/whoq"
  license "MIT"

  on_macos do
    on_arm do
      url "${base}/whoq-${tag}-aarch64-apple-darwin.tar.gz"
      sha256 "$(sha aarch64-apple-darwin)"
    end
    on_intel do
      url "${base}/whoq-${tag}-x86_64-apple-darwin.tar.gz"
      sha256 "$(sha x86_64-apple-darwin)"
    end
  end

  on_linux do
    on_arm do
      url "${base}/whoq-${tag}-aarch64-unknown-linux-musl.tar.gz"
      sha256 "$(sha aarch64-unknown-linux-musl)"
    end
    on_intel do
      url "${base}/whoq-${tag}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "$(sha x86_64-unknown-linux-musl)"
    end
  end

  def install
    bin.install "whoq"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/whoq --version")
  end
end
RUBY
