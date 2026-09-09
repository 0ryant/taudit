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
  version "1.3.3"
  license "AGPL-3.0-or-later"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/0ryant/taudit/releases/download/v#{version}/taudit-aarch64-macos.tar.gz"
      sha256 "f4fad2ae7945973cffb2b56aeb73038319cb75bb0c65f75a8a43ef74d469792a"
    else
      url "https://github.com/0ryant/taudit/releases/download/v#{version}/taudit-x86_64-macos.tar.gz"
      sha256 "476882bbc013f934b3cafdd5c7a5a84af4ecd33d2598f54a485b312ece9fff5f"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/0ryant/taudit/releases/download/v#{version}/taudit-aarch64-linux.tar.gz"
      sha256 "9d2f5ddce79d07c98e07ea698d2826b0b9d3a0944e20c2067fe768d0e7a6acb4"
    else
      url "https://github.com/0ryant/taudit/releases/download/v#{version}/taudit-x86_64-linux.tar.gz"
      sha256 "651dde139fbe38807555010b26c1b0ef6605374e2f0339d34f140d62494ff657"
    end
  end

  def install
    bin.install "taudit"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/taudit --version")
  end
end