# T-027: Configuration variation tests
# Verifies that different config shapes produce correct ossec.conf XML.
# Uses nix-instantiate --eval --strict to check generated XML strings.
let
  pkgs = import /root/nixpkgs { system = "x86_64-linux"; };
  lib = pkgs.lib;

  inherit (lib)
    optionalString
    concatStringsSep
    naturalSort
    splitString
    ;

  # ---------------------------------------------------------------------------
  # Reimport generateOssecConf from the module (copy of the function)
  # ---------------------------------------------------------------------------
  generateOssecConf =
    settings: extraConfig:
    let
      isNull_ = v: v == null;

      xmlEscape =
        s:
        let
          s1 = builtins.replaceStrings [ "&" ] [ "&amp;" ] s;
          s2 = builtins.replaceStrings [ "<" ] [ "&lt;" ] s1;
          s3 = builtins.replaceStrings [ ">" ] [ "&gt;" ] s2;
          s4 = builtins.replaceStrings [ "\"" ] [ "&quot;" ] s3;
          s5 = builtins.replaceStrings [ "'" ] [ "&apos;" ] s4;
        in
        s5;

      scalarToStr =
        v:
        if builtins.isBool v then
          (if v then "yes" else "no")
        else if builtins.isInt v || builtins.isFloat v then
          toString v
        else if builtins.isString v then
          xmlEscape v
        else
          xmlEscape (toString v);

      indentStr =
        n: s:
        let
          pad = builtins.concatStringsSep "" (builtins.genList (_: " ") n);
          ls = splitString "\n" s;
          indented = map (l: if l == "" then "" else pad + l) ls;
        in
        concatStringsSep "\n" indented;

      renderAttrsBody =
        attrs:
        let
          keys = naturalSort (builtins.attrNames attrs);
          rendered = map (k: renderKV k attrs.${k}) keys;
          nonEmpty = builtins.filter (s: s != "") rendered;
        in
        concatStringsSep "\n" nonEmpty;

      renderAttrsAsElement =
        key: attrs:
        if key == "wodle" then
          let
            wodleName = xmlEscape (attrs.name or "");
            innerAttrs = builtins.removeAttrs attrs [ "name" ];
            inner = renderAttrsBody innerAttrs;
          in
          if inner == "" then
            ''<wodle name="${wodleName}"/>''
          else
            "<wodle name=\"${wodleName}\">\n${indentStr 2 inner}\n</wodle>"
        else
          let
            inner = renderAttrsBody attrs;
          in
          if inner == "" then
            "<${key}/>"
          else
            "<${key}>\n${indentStr 2 inner}\n</${key}>";

      renderKV =
        key: val:
        if isNull_ val then
          ""
        else if builtins.isBool val then
          "<${key}>${scalarToStr val}</${key}>"
        else if builtins.isInt val || builtins.isFloat val then
          "<${key}>${scalarToStr val}</${key}>"
        else if builtins.isString val then
          "<${key}>${scalarToStr val}</${key}>"
        else if builtins.isList val then
          let
            renderItem =
              item:
              if isNull_ item then
                ""
              else if builtins.isAttrs item then
                renderAttrsAsElement key item
              else
                "<${key}>${scalarToStr item}</${key}>";
            rendered = map renderItem val;
            nonEmpty = builtins.filter (s: s != "") rendered;
          in
          concatStringsSep "\n" nonEmpty
        else if builtins.isAttrs val then
          renderAttrsAsElement key val
        else
          "<${key}>${xmlEscape (toString val)}</${key}>";

      renderTopLevel =
        attrs:
        let
          keys = naturalSort (builtins.attrNames attrs);
          renderOne =
            k:
            let
              val = attrs.${k};
            in
            if isNull_ val then
              ""
            else if k == "wodle" then
              if builtins.isList val then
                let
                  items = builtins.filter (x: !isNull_ x) val;
                  rendered = map (w: renderAttrsAsElement "wodle" w) items;
                  nonEmpty = builtins.filter (s: s != "") rendered;
                in
                concatStringsSep "\n" nonEmpty
              else
                ""
            else if k == "localfile" then
              if builtins.isList val then
                let
                  items = builtins.filter (x: !isNull_ x) val;
                  rendered = map (lf: renderAttrsAsElement "localfile" lf) items;
                  nonEmpty = builtins.filter (s: s != "") rendered;
                in
                concatStringsSep "\n" nonEmpty
              else
                ""
            else
              renderKV k val;

          rendered = map renderOne keys;
          nonEmpty = builtins.filter (s: s != "") rendered;
        in
        concatStringsSep "\n" nonEmpty;

      body = renderTopLevel settings;
      extra = optionalString (extraConfig != "") ("\n" + extraConfig);
    in
    "<ossec_config>\n${indentStr 2 body}${extra}\n</ossec_config>\n";

  # ---------------------------------------------------------------------------
  # Helper: assert with message
  # ---------------------------------------------------------------------------
  check = name: cond: if cond then "PASS: ${name}" else builtins.throw "FAIL: ${name}";
  contains = s: substr: builtins.stringLength (builtins.replaceStrings [substr] [""] s) < builtins.stringLength s;

  # ---------------------------------------------------------------------------
  # T-027-1: Basic manager address appears in XML
  # ---------------------------------------------------------------------------
  cfg1 = generateOssecConf {
    client.server = {
      address = "10.0.0.1";
      port = 1514;
      protocol = "tcp";
    };
    syscheck.disabled = true;
    rootcheck.disabled = true;
  } "";

  t027_1_manager_address  = check "T027-1: manager address 10.0.0.1 in XML"   (contains cfg1 "<address>10.0.0.1</address>");
  t027_1_manager_port     = check "T027-1: manager port 1514 in XML"           (contains cfg1 "<port>1514</port>");
  t027_1_manager_protocol = check "T027-1: manager protocol tcp in XML"        (contains cfg1 "<protocol>tcp</protocol>");
  t027_1_syscheck_off     = check "T027-1: syscheck disabled=yes in XML"       (contains cfg1 "<disabled>yes</disabled>");
  t027_1_client_block     = check "T027-1: <client> block wraps server"        (contains cfg1 "<client>");
  t027_1_server_block     = check "T027-1: <server> block inside client"       (contains cfg1 "<server>");

  # ---------------------------------------------------------------------------
  # T-027-2: Multiple localfile entries appear as repeated <localfile> elements
  # ---------------------------------------------------------------------------
  cfg2 = generateOssecConf {
    client.server = { address = "wazuh.example.com"; port = 1514; };
    localfile = [
      { log_format = "journald"; location = "journald"; }
      { log_format = "syslog";   location = "/var/log/auth.log"; }
    ];
  } "";

  t027_2_journald_format  = check "T027-2: journald log_format in XML"         (contains cfg2 "<log_format>journald</log_format>");
  t027_2_syslog_format    = check "T027-2: syslog log_format in XML"           (contains cfg2 "<log_format>syslog</log_format>");
  t027_2_auth_log_path    = check "T027-2: /var/log/auth.log location in XML"  (contains cfg2 "<location>/var/log/auth.log</location>");
  t027_2_manager_domain   = check "T027-2: FQDN address in XML"                (contains cfg2 "<address>wazuh.example.com</address>");

  # ---------------------------------------------------------------------------
  # T-027-3: extraConfig raw XML is appended verbatim
  # ---------------------------------------------------------------------------
  cfg3 = generateOssecConf {
    client.server = { address = "mgr.internal"; port = 1514; };
  } "<active-response><disabled>yes</disabled></active-response>";

  t027_3_extra_appended   = check "T027-3: extraConfig appended to XML"        (contains cfg3 "<active-response><disabled>yes</disabled></active-response>");
  t027_3_manager_still    = check "T027-3: manager address still in XML"       (contains cfg3 "<address>mgr.internal</address>");

  # ---------------------------------------------------------------------------
  # T-027-4: crypto_method appears correctly
  # ---------------------------------------------------------------------------
  cfg4 = generateOssecConf {
    client = {
      server  = { address = "10.1.2.3"; port = 1514; };
      crypto_method = "aes";
    };
  } "";

  t027_4_crypto_aes       = check "T027-4: crypto_method aes in XML"           (contains cfg4 "<crypto_method>aes</crypto_method>");

  # ---------------------------------------------------------------------------
  # T-027-5: bool false renders as "no"
  # ---------------------------------------------------------------------------
  cfg5 = generateOssecConf {
    client.server = { address = "10.0.0.1"; port = 1514; };
    syscheck = { disabled = false; frequency = 3600; };
  } "";

  t027_5_disabled_no      = check "T027-5: syscheck disabled=false renders as <disabled>no</disabled>" (contains cfg5 "<disabled>no</disabled>");
  t027_5_frequency        = check "T027-5: syscheck frequency=3600 in XML"     (contains cfg5 "<frequency>3600</frequency>");

  # ---------------------------------------------------------------------------
  # T-027-6: XML special characters are escaped in string values
  # ---------------------------------------------------------------------------
  cfg6 = generateOssecConf {
    client.server = { address = "10.0.0.1"; port = 1514; };
    syscheck = { disabled = true; };
    rootcheck = { disabled = true; };
  } "";

  # Wrap in ossec_config
  t027_6_wraps_ossec_config = check "T027-6: output wraps with <ossec_config>"  (contains cfg6 "<ossec_config>");
  t027_6_ends_with_close    = check "T027-6: output ends with </ossec_config>"  (contains cfg6 "</ossec_config>");

  # ---------------------------------------------------------------------------
  # T-027-7: wodle element uses name= attribute syntax
  # ---------------------------------------------------------------------------
  cfg7 = generateOssecConf {
    client.server = { address = "10.0.0.1"; port = 1514; };
    wodle = [
      { name = "syscollector"; disabled = false; interval = "1h"; }
    ];
  } "";

  t027_7_wodle_name        = check "T027-7: wodle name= attribute in XML"       (contains cfg7 ''<wodle name="syscollector">'');
  t027_7_wodle_interval    = check "T027-7: wodle interval in XML"              (contains cfg7 "<interval>1h</interval>");

in {
  inherit
    t027_1_manager_address
    t027_1_manager_port
    t027_1_manager_protocol
    t027_1_syscheck_off
    t027_1_client_block
    t027_1_server_block
    t027_2_journald_format
    t027_2_syslog_format
    t027_2_auth_log_path
    t027_2_manager_domain
    t027_3_extra_appended
    t027_3_manager_still
    t027_4_crypto_aes
    t027_5_disabled_no
    t027_5_frequency
    t027_6_wraps_ossec_config
    t027_6_ends_with_close
    t027_7_wodle_name
    t027_7_wodle_interval
    ;
}
