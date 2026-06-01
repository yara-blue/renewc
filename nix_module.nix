{
  config,
  lib,
  pkgs,
  ...
}:

with lib;
with lib.types;
let
  cfg = config.services.break-enforcer;
in
{
  options = {
    services.break-enforcer = {
      enable = mkEnableOption "renewc";
      work-duration = mkOption {
        type = types.str;
        description = "Period after which input will be disabled. Note:
				run help command to see the duration format";
      };
      break-duration = mkOption {
        type = types.str;
        description = "Length of the (short) breaks, after this period
				input is resumed. Note: run help command to see the duration
				format";
      };
      long-break-duration = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Length of the long breaks, after this period
				input is resumed. Note: run help command to see the duration
				format";
      };
      work-between-long-breaks = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Amount of total work time before next break will
				be a long break. Note: run help command to see the duration
				format";
      };
      break-start-lead = mkOption {
        type = types.str;
        description = "How long before a break starts to send a
				notification. Note: run help command to see the duration
				format";
        default = "30s";
      };
      break-end-lead = mkOption {
        type = types.str;
        description = "How long before a break starts to send a
				notification. Note: run help command to see the duration
				format";
        default = "5s";
      };
      work-reset-lead = mkOption {
        type = types.str;
        description = "How long before the work period resets to send a
				notification. Note: run help command to see the duration
				format";
        default = "5s";
      };
      break-start-notify = mkOption {
        type = listOf (types.str);
        default = [ ];
        description = ''
          Type of notification to get when break is about to begin.
          Options: [audio, system, command(<command string>)].
          The command string should be a space separated list of the program
          to run and its arguments. Spaces in arguments are not supported.
          Example: command(killall minecraft)'';
      };
      break-end-notify = mkOption {
        type = listOf (types.str);
        default = [ ];
        description = ''
          Type of notification to get when break is about to end.
          Options: [audio, system, command(<command string>)].
          The command string should be a space separated list of the program
          to run and its arguments. Spaces in arguments are not supported.
          Example: command(killall minecraft)'';
      };
      work-reset-notify = mkOption {
        type = listOf (types.str);
        default = [ ];
        description = ''
          Type of notification to get when the work time resets.
          Options: [audio, system, command(<command string>)].
          The command string should be a space separated list of the program
          to run and its arguments. Spaces in arguments are not supported.
          Example: command(killall minecraft)'';
      };
      tcp-api = mkEnableOption "tcp-api";
      status-file = mkEnableOption "status-file";
      notifications = mkEnableOption "notifications";
    };
  };

  config = mkIf cfg.enable {
    systemd.services.renewc = {
      description = "Renew certificates";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "simple";
        ExecStart = ''
          ${pkgs.renewc}/bin/renewc run \
          --work-duration ${cfg.work-duration} \
          --break-duration ${cfg.break-duration} \
           ${
             optionalString (cfg.long-break-duration != null) "--long-break-duration ${cfg.long-break-duration}"
           } \
           ${
             optionalString (
               cfg.work-between-long-breaks != null
             ) "--work-between-long-breaks ${cfg.work-between-long-breaks}"
           } \
          --break-start-lead ${cfg.break-start-lead} \
          --break-end-lead ${cfg.break-end-lead} \
          --work-reset-lead ${cfg.work-reset-lead} \
          ${concatMapStrings (x: "--break-start-notify " + "\"" + x + "\" ") cfg.break-start-notify} \
          ${concatMapStrings (x: "--break-end-notify " + "\"" + x + "\" ") cfg.break-end-notify} \
          ${concatMapStrings (x: "--work-reset-notify " + "\"" + x + "\" ") cfg.work-reset-notify} \
          ${optionalString cfg.tcp-api "--tcp-api"} \
          ${optionalString cfg.status-file "--status-file"} \
          ${optionalString cfg.notifications "--notifications"}
        '';
      };
    };
  };
}
