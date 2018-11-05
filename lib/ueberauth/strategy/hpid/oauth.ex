defmodule Ueberauth.Strategy.HPID.OAuth do
  @moduledoc """
  An implementation of OAuth2 for HP ID.

  To add your `client_id` and `client_secret` include these values in your configuration.

      config :ueberauth, Ueberauth.Strategy.HPID.OAuth,
        client_id: System.get_env("HPID_CLIENT_ID"),
        client_secret: System.get_env("HPID_CLIENT_SECRET")
  """
  use OAuth2.Strategy

  # production host
  @prod_host "https://directory.id.hp.com"
  # staging host
  @stage_host "https://directory.stg.cd.id.hp.com"

  @doc """
  Construct a client for requests to HP ID.

  Optionally include any OAuth2 options here to be merged with the defaults.

      Ueberauth.Strategy.HPID.OAuth.client(redirect_uri: "http://localhost:4000/auth/hpid/callback")

  This will be setup automatically for you in `Ueberauth.Strategy.HPID`.
  These options are only useful for usage outside the normal callback phase of Ueberauth.
  """
  def client(opts \\ []) do
    config =
      :ueberauth
      |> Application.fetch_env!(Ueberauth.Strategy.HPID.OAuth)
      |> check_config_key_exists(:client_id)
      |> check_config_key_exists(:client_secret)

    client_opts =
      defaults()
      |> Keyword.merge(config)
      |> Keyword.merge(opts)

    OAuth2.Client.new(client_opts)
  end

  @doc """
  Provides the authorize url for the request phase of Ueberauth. No need to call this usually.
  """
  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.authorize_url!(params)
  end

  def get(token, url, headers \\ [], opts \\ []) do
    [token: token]
    |> client
    |> put_param("client_secret", client().client_secret)
    |> OAuth2.Client.get(url, headers, opts)
  end

  def get_token!(params \\ [], options \\ []) do
    headers = Keyword.get(options, :headers, [])
    options = Keyword.get(options, :options, [])
    client_options = Keyword.get(options, :client_options, [])
    client = OAuth2.Client.get_token!(client(client_options), params, headers, options)
    client.token
  end

  @doc ~S"""
  Validate a token, by matching the active status
  and client_id.
  """
  @spec validate(String.t) :: boolean()
  def validate(token) do
    client_id =
      :ueberauth
      |> Application.fetch_env!(Ueberauth.Strategy.HPID.OAuth)
      |> Keyword.get(:client_id)

    case __MODULE__.get(token, "/directory/v1/oauth/validate") do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        false

      {:ok, %OAuth2.Response{status_code: status_code, body: user}}
      when status_code in 200..399 ->
        case user do
          %{"active": true,
            "client_id": ^client_id} -> true
          _ -> false
        end
      {:error, %OAuth2.Error{reason: _}} ->
        false
    end
  end

  # Strategy Callbacks

  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client
    |> put_param("client_secret", client.client_secret)
    |> put_header("Accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
  end

  def defaults do
    site_host = host()

    [
      strategy: __MODULE__,
      site: site_host,
      authorize_url: "#{site_host}/directory/v1/oauth/authorize",
      token_url: "#{site_host}/directory/v1/oauth/token"
    ]
  end

  defp check_config_key_exists(config, key) when is_list(config) do
    unless Keyword.has_key?(config, key) do
      raise "#{inspect(key)} missing from config :ueberauth, Ueberauth.Strategy.HPID"
    end

    config
  end

  defp check_config_key_exists(_, _) do
    raise "Config :ueberauth, Ueberauth.Strategy.HPID is not a keyword list, as expected"
  end

  defp host do
    case config()[:use_stage] do
      true -> @stage_host
      _ -> @prod_host
    end
  end

  defp config do
    Application.fetch_env!(:ueberauth, Ueberauth.Strategy.HPID.OAuth)
  end
end
