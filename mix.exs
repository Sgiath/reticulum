defmodule Reticulum.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      # Library
      app: :reticulum,
      version: @version,

      # Elixir
      elixir: "~> 1.16",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      consolidate_protocols: Mix.env() != :test,
      deps: deps(),

      # Docs
      name: "reticulum",
      source_url: "https://github.com/Sgiath/reticulum",
      homepage_url: "https://sgiath.dev/libraries#reticulum",
      description: """
      Elixir implementation of Reticulum protocol
      """,
      package: package(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      # Development
      {:ex_check, "~> 0.15", only: [:dev], runtime: false, optional: true},
      {:credo, "~> 1.7", only: [:dev], runtime: false, optional: true},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false, optional: true},
      {:ex_doc, "~> 0.31", only: [:dev], runtime: false, optional: true},
      {:mix_audit, "~> 2.1", only: [:dev], runtime: false, optional: true},
      {:mix_test_watch, "~> 1.1", only: [:dev], runtime: false, optional: true}
    ]
  end

  defp package do
    [
      name: "reticulum",
      maintainers: ["Sgiath <reticulum@sgiath.dev>"],
      files: ~w(lib LICENSE mix.exs README* CHANGELOG*),
      licenses: ["WTFPL"],
      links: %{
        "Homepage" => "https://reticulum.network",
        "GitHub" => "https://github.com/Sgiath/reticulum"
      }
    ]
  end

  defp docs do
    [
      authors: ["sgiath <reticulum@sgiath.dev>"],
      main: "readme",
      api_reference: false,
      extras: [
        "README.md": [filename: "readme", title: "Overview"],
        "CHANGELOG.md": [filename: "changelog", title: "Changelog"]
      ],
      formatters: ["html"],
      source_ref: "v#{@version}",
      source_url: "https://github.com/Sgiath/reticulum"
    ]
  end
end
