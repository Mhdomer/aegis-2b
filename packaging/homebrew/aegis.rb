class Aegis < Formula
  include Language::Python::Virtualenv

  desc "Autonomous Cloud Ops Safety Circuit Breaker using Strands Decider 2B"
  homepage "https://mhdomer.github.io/aegis-2b/"
  url "https://github.com/Mhdomer/aegis-2b/archive/refs/tags/v0.2.0.tar.gz"
  license "MIT"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    system "#{bin}/aegis", "--version"
    system "#{bin}/aegis", "audit"
  end
end
