# Homebrew formula for taudit (third-party tap).
# https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap
#
# 1. Create a repo named homebrew-taudit (or homebrew-tap) on GitHub.
# 2. Copy this file into that repo as Formula/taudit.rb.
# 3. Cut a GitHub release that uploads the archives referenced below.
# 4. Replace each YOUR_SHA256_HERE value with the real archive hash.
# 5. Users install with: brew tap YOUR_GITHUB/taudit && brew install taudit

class Taudit < Formula
  desc "CI/CD authority scanner for secrets, identities, and trust boundaries"
  homepage "https://github.com/0ryant/taudit"
  version "0.1.1"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/0ryant/taudit/releases/download/v#{version}/taudit-aarch64-macos.tar.gz"
      sha256 "YOUR_SHA256_HERE"
    else
      url "https://github.com/0ryant/taudit/releases/download/v#{version}/taudit-x86_64-macos.tar.gz"
      sha256 "YOUR_SHA256_HERE"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/0ryant/taudit/releases/download/v#{version}/taudit-aarch64-linux.tar.gz"
      sha256 "YOUR_SHA256_HERE"
    else
      url "https://github.com/0ryant/taudit/releases/download/v#{version}/taudit-x86_64-linux.tar.gz"
      sha256 "YOUR_SHA256_HERE"
    end
  end

  def install
    bin.install "taudit"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/taudit --version")
  end
end