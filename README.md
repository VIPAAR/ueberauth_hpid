# Ueberauth HPID

> HP ID OAuth2 strategy for Überauth.

## Installation

1. Add `:ueberauth_hpid` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [{:ueberauth_hpid, "~> 1.0"}]
    end
    ```

1. Add the strategy to your applications:

    ```elixir
    def application do
      [applications: [:ueberauth_hpid]]
    end
    ```

1. Add HPID to your Überauth configuration:

    ```elixir
    config :ueberauth, Ueberauth,
      providers: [
        hpid: {Ueberauth.Strategy.HPID, []}
      ]
    ```

1.  Update your provider configuration:

    ```elixir
    config :ueberauth, Ueberauth.Strategy.HPID.OAuth,
      client_id: System.get_env("HPID_CLIENT_ID"),
      client_secret: System.get_env("HPID_CLIENT_SECRET")
    ```

1.  Include the Überauth plug in your controller:

    ```elixir
    defmodule MyApp.AuthController do
      use MyApp.Web, :controller

      pipeline :browser do
        plug Ueberauth
        ...
       end
    end
    ```

1.  Create the request and callback routes if you haven't already:

    ```elixir
    scope "/auth", MyApp do
      pipe_through :browser

      get "/:provider", AuthController, :request
      get "/:provider/callback", AuthController, :callback
    end
    ```

1. Your controller needs to implement callbacks to deal with `Ueberauth.Auth` and `Ueberauth.Failure` responses.

For an example implementation see the [Überauth Example](https://github.com/ueberauth/ueberauth_example) application.

## Calling

Depending on the configured url you can initiate the request through:

    /auth/hpid

Or with options:

    /auth/hpid?scope=openid+profile+email
    
Or if using token workflow:

    /auth/hpid/callback?token=xyz

By default the requested scope is "openid+profile+email". This provides both read access to the HPID user profile. See more at [HPID's OAuth Documentation](https://developers.hp.com/hp-id/doc/authn-scopes). Scope can be configured either explicitly as a `scope` query value on the request path or in your configuration:

```elixir
config :ueberauth, Ueberauth,
  providers: [
    hpid: {Ueberauth.Strategy.HPID, [
      default_scope: "openid+profile+email",
      redirect_uri: "https://yourdomain.com"
    ]}
  ]
```

If you need to override the callback url (redirect_uri) at runtime, you can use the 
configuration in the Ueberauth.Strategy.HPID.OAuth:

```elixir
    config :ueberauth, Ueberauth.Strategy.HPID.OAuth,
      client_id: System.get_env("HPID_CLIENT_ID"),
      client_secret: System.get_env("HPID_CLIENT_SECRET"),
      redirect_uri: "https://yourdomain.com/auth/hpid/callback"
```

## License

Please see [LICENSE](https://github.com/VIPAAR/ueberauth_hpid/blob/master/LICENSE) for licensing details.

