# Homebrew formula for taudit (third-party tap).
# https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap
#
# Do NOT hand-edit the version or the sha256 values: run `just homebrew-sync`
# after the release archives exist, and it fills both from the published
# `<archive>.sha256` sidecars. It errors rather than writing a placeholder if an
# archive is missing, so this file is either fully truthful for a version or the
# command fails.
#
# To publish: create a public repo named homebrew-taudit, copy this file into it
# as Formula/taudit.rb, and push. Users then install with:
#   brew tap 0ryant/taudit && brew install taudit
# That tap repo does not exist yet, so no brew install path is documented in the
# README. See ../RELEASE-CHANNELS.md.

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