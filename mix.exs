defmodule UeberauthHPID.MixProject do
  use Mix.Project

  @version "1.0.0"

  def project do
    [
      app: :ueberauth_hpid,
      version: @version,
      name: "Ueberauth HPID",
      package: package(),
      elixir: "~> 1.5",
      start_permanent: Mix.env() == :prod,
      source_url: "https://github.com/VIPAAR/ueberauth_hpid",
      homepage_url: "https://github.com/VIPAAR/ueberauth_hpid",
      description: description(),
      deps: deps(),
      docs: docs()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :ueberauth, :oauth2]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:oauth2, "~> 0.9"},
      {:ueberauth, "~> 0.4"},

      # dev/test only dependencies
      {:credo, "~> 0.8", only: [:dev, :test]},

      # docs dependencies
      {:earmark, ">= 0.0.0", only: :dev},
      {:ex_doc, ">= 0.0.0", only: :dev}
    ]
  end

  defp docs do
    [extras: ["README.md"]]
  end

  defp description do
    "An Ueberauth strategy for using HP ID to authenticate your users."
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README.md", "LICENSE"],
      maintainers: ["Marcus Dillavou"],
      licenses: ["MIT"],
      links: %{GitHub: "https://github.com/VIPAAR/ueberauth_hpid"}
    ]
  end
end
