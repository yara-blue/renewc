{
  config,
  lib,
  pkgs,
  ...
}:

with lib;
with lib.types;
let
  cfg = config.services.renewc;
in
{
  options = {
    services.renewc = {
      enable = mkEnableOption "renewc, automatic Let's Encrypt certificate renewal";

      user = mkOption {
        type = types.str;
        default = "renewc";
        description = "User account under which renewc runs.";
      };

      group = mkOption {
        type = types.str;
        default = "renewc";
        description = "Group account under which renewc runs.";
      };

      time = mkOption {
        type = types.str;
        default = "04:00";
        example = "03:30";
        description = ''
          Time of day (HH:MM) at which the renewal check runs. renewc
          itself decides whether a certificate is actually due for renewal
          (it renews roughly 8 to 10 days before expiry), so it is safe and
          recommended to run the check once a day.
        '';
      };

      domains = mkOption {
        type = listOf types.str;
        example = [
          "example.org"
          "www.example.org"
        ];
        description = ''
          Domain(s) to request a certificate for. To request a certificate
          covering multiple subdomains pass multiple domains here; note the
          base domain must be the same for all of them.
        '';
      };

      email = mkOption {
        type = listOf types.str;
        default = [ ];
        example = [ "you@example.org" ];
        description = "Contact info supplied to the ACME provider.";
      };

      production = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Use the Let's Encrypt production environment instead of staging.
          See https://letsencrypt.org/docs/staging-environment/.
        '';
      };

      port = mkOption {
        type = types.port;
        default = 80;
        description = ''
          Internal port that external port 80 should be forwarded to. renewc
          listens on this port to answer the ACME HTTP-01 challenge.
        '';
      };

      reload = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "haproxy.service";
        description = "Systemd service to reload after a successful renewal.";
      };

      renewEarly = mkOption {
        type = types.bool;
        default = false;
        description = "Renew a certificate even if it is not yet due.";
      };

      force = mkOption {
        type = types.bool;
        default = false;
        description = "Ignore existing certificates and always renew.";
      };

      overwriteProduction = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Request a staging certificate even if doing so would overwrite a
          valid production certificate.
        '';
      };

      debug = mkOption {
        type = types.bool;
        default = false;
        description = "Enable debug logging.";
      };

      output = mkOption {
        type = types.enum [
          "pem-single-file"
          "pem-seperate-key"
          "pem-seperate-chain"
          "pem-all-seperate"
          "der"
        ];
        default = "pem-seperate-key";
        description = ''
          How to encode and split the certificate, chain and private key
          across files. See `renewc run --help` for a description of each
          variant (for example `pem-single-file` is what Haproxy expects and
          `pem-seperate-key` is what Nginx and Apache expect).
        '';
      };

      certificatePath = mkOption {
        type = types.path;
        example = "/var/lib/renewc/example.org";
        description = ''
          Path, optionally including a file name, where the signed
          certificate (possibly together with its private key and/or chain,
          depending on the selected output format) is written. The correct
          file extension is added automatically when no name is given.
        '';
      };

      keyPath = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = ''
          Path, optionally including a file name, where the private key is
          written when it is stored separately from the certificate. Defaults
          to the certificate-path's directory when unset.
        '';
      };

      chainPath = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = ''
          Path, optionally including a file name, where the certificate chain
          is written when it is stored separately. Defaults to being deduced
          from the certificate-path when unset. Cannot be used with the `der`
          output format.
        '';
      };
    };
  };

  config = mkIf cfg.enable {
    systemd.services.renewc = {
      description = "Renew TLS certificates with renewc";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      serviceConfig = {
        Type = "oneshot";
        User = cfg.user;
        Group = cfg.group;
        AmbientCapabilities = optional (cfg.port < 1024) "CAP_NET_BIND_SERVICE";
        ExecStart = concatStringsSep " " (
          [
            "${pkgs.renewc}/bin/renewc run"
          ]
          ++ map (d: "--domain ${escapeShellArg d}") cfg.domains
          ++ map (e: "--email ${escapeShellArg e}") cfg.email
          ++ optional cfg.production "--production"
          ++ [ "--port ${toString cfg.port}" ]
          ++ optional (cfg.reload != null) "--reload ${escapeShellArg cfg.reload}"
          ++ optional cfg.renewEarly "--renew-early"
          ++ optional cfg.force "--force"
          ++ optional cfg.overwriteProduction "--overwrite-production"
          ++ optional cfg.debug "--debug"
          ++ [ "--output ${cfg.output}" ]
          ++ [ "--certificate-path ${escapeShellArg (toString cfg.certificatePath)}" ]
          ++ optional (cfg.keyPath != null) "--key-path ${escapeShellArg (toString cfg.keyPath)}"
          ++ optional (cfg.chainPath != null) "--chain-path ${escapeShellArg (toString cfg.chainPath)}"
        );
      };
    };

    # allow reloading the configured systemd service
    security.polkit.enable = mkIf (cfg.reload != null) true;
    security.polkit.extraConfig = mkIf (cfg.reload != null) ''
      polkit.addRule(function(action, subject) {
        if (action.id == "org.freedesktop.systemd1.manage-units" &&
            subject.user == ${builtins.toJSON cfg.user}) {
          if (action.lookup("unit") == ${builtins.toJSON cfg.reload} &&
              action.lookup("verb") == "reload") {
            return polkit.Result.YES;
          }
        }
      });
    '';

    systemd.timers.renewc = {
      description = "Daily timer for renewc certificate renewal";
      wantedBy = [ "timers.target" ];

      timerConfig = {
        OnCalendar = "*-*-* ${cfg.time}:00";
        Persistent = true;
        Unit = "renewc.service";
      };
    };

    # create default user/group if used
    # (shamelessly stolen from haproxy flake)
    users.users = optionalAttrs (cfg.user == "renewc") {
      renewc = {
        group = cfg.group;
        isSystemUser = true;
      };
    };

    users.groups = optionalAttrs (cfg.group == "renewc") {
      renewc = { };
    };
  };
}
