function main(config) {

  // ================================================================
  // Clash Mi / Mihomo Custom Rules v1.7
  // ================================================================


  // ================================================================
  // 1. Basic configuration
  // ================================================================

  config["mixed-port"] = 7890;

  config["mode"] = "rule";

  config["unified-delay"] = true;

  config["tcp-concurrent"] = true;

  config["log-level"] = "error";

  config["ipv6"] = false;

  config["allow-lan"] = false;

  config["find-process-mode"] = "always";

  config["keep-alive-interval"] = 30;

  config["keep-alive-idle"] = 30;

  config["disable-keep-alive"] = false;


  // ================================================================
  // 2. Profile
  // ================================================================

  config["profile"] = {

    "store-selected": true,

    "store-fake-ip": true

  };


  // ================================================================
  // 3. DNS
  // ================================================================

  config["dns"] = {

    "enable": true,

    "listen": "0.0.0.0:53",

    "prefer-h3": false,

    "ipv6": false,

    "enhanced-mode": "fake-ip",

    "fake-ip-range": "172.19.0.1/16",

    "fake-ip-filter": [

      "+.lan",
      "+.local",
      "+.localhost",
      "+.home.arpa",

      "time.*.com",
      "time.*.gov",
      "pool.ntp.org",

      "+.push.apple.com",

      "mesu.apple.com",
      "swscan.apple.com",

      "captive.apple.com",

      "connectivitycheck.gstatic.com",

      "connectivitycheck.android.com",

      "www.msftconnecttest.com",

      "www.msftncsi.com"

    ],

    "default-nameserver": [

      "223.5.5.5",
      "119.29.29.29"

    ],

    "nameserver": [

      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"

    ],

    "nameserver-policy": {

      "geosite:cn": [

        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query"

      ],

      "geosite:private": [

        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query"

      ],

      "geolocation-!cn": [

        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/dns-query"

      ]

    },

    "proxy-server-nameserver": [

      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"

    ],

    "direct-nameserver": [

      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"

    ],

    "fallback": [

      "https://cloudflare-dns.com/dns-query",
      "https://dns.google/dns-query"

    ],

    "fallback-filter": {

      "geoip": true,

      "geoip-code": "CN",

      "geosite": [

        "gfw"

      ],

      "domain": [

        "+.google.com",
        "+.googleapis.com",
        "+.googlevideo.com",
        "+.youtube.com",
        "+.github.com",
        "+.openai.com",
        "+.chatgpt.com",
        "+.anthropic.com",
        "+.claude.ai"

      ]

    }

  };


  // ================================================================
  // 4. TUN
  // ================================================================

  config["tun"] = {

    "enable": true,

    "device": "Clash Mi",

    "stack": "gvisor",

    "dns-hijack": [

      "0.0.0.0:53"

    ],

    "auto-route": true,

    "auto-detect-interface": false,

    "strict-route": true,

    "mtu": 1280,

    "inet4-address": [

      "172.19.0.1/30"

    ],

    "auto-redirect": false,

    "disable-icmp-forwarding": true

  };


  // ================================================================
  // 5. Sniffer
  // ================================================================

  config["sniffer"] = {

    "enable": true,

    "parse-pure-ip": true,

    "force-dns-mapping": true,

    "override-destination": true,

    "sniff": {

      "HTTP": {

        "ports": [

          80,
          "8080-8880"

        ]

      },

      "TLS": {

        "ports": [

          443,
          8443

        ]

      },

      "QUIC": {

        "ports": [

          443,
          8443

        ]

      }

    },

    "skip-domain": [

      "+.push.apple.com",
      "+.mijia.cloud"

    ]

  };


  // ================================================================
  // 6. NTP
  // ================================================================

  config["ntp"] = {

    "enable": true,

    "write-to-system": false,

    "server": "time.apple.com",

    "port": 123,

    "interval": 30

  };


  // ================================================================
  // 7. Extract proxies from subscription
  // ================================================================

  var originalProxies = Array.isArray(config["proxies"])
    ? config["proxies"]
    : [];


  var proxyNames = [];

  originalProxies.forEach(function(proxy) {

    if (proxy && proxy.name) {

      proxyNames.push(proxy.name);

    }

  });


  // ================================================================
  // 8. Icons & CDN
  // ================================================================

  var iconBaseURL =
    "https://cdn.jsdelivr.net/gh/n0de-sudo/Perfect-Rules@main/Clash/icons/";


  var groupIcons = {

    "节点选择": "Proxy.png",

    "自动选择": "Auto.png",

    "漏网之鱼": "Final.png",

    "一键代理": "Proxy.png",

    "国内直连": "China.png",

    "AI": "AI.png",

    "YouTube": "YouTube.png",

    "Google": "Google.png",

    "GitHub": "GitHub.png",

    "网络检测": "Network-test.png",

    "Netflix": "Netflix.png",

    "Spotify": "Spotify.png",

    "Steam": "Steam.png",

    "Telegram": "Telegram.png",

    "TikTok": "TikTok.png",

    "Apple": "Apple.png",

    "Microsoft": "Microsoft.png",

    "香港": "Hong_Kong.png",

    "台湾": "Taiwan.png",

    "日本": "Japan.png",

    "新加坡": "Singapore.png",

    "韩国": "Korea.png",

    "美国": "United_States.png",

    "加拿大": "Other.png",

    "英国": "Other.png",

    "其他地区": "Other.png"

  };


  function getGroupIcon(name) {

    if (!groupIcons[name]) {

      return undefined;

    }

    return iconBaseURL + groupIcons[name];

  }


  // ================================================================
  // 9. Remote Rule Providers
  // ================================================================

  var ruleBaseURL =
    "https://cdn.jsdelivr.net/gh/n0de-sudo/Perfect-Rules@main/Clash/rules/";


  function createRuleProvider(filename) {

    return {

      "type": "http",

      "behavior": "classical",

      "format": "yaml",

      "url": ruleBaseURL + filename,

      "path": "./rules/" + filename,

      "interval": 86400

    };

  }


  config["rule-providers"] = {

    "AI": createRuleProvider("ai.yaml"),

    "YouTube": createRuleProvider("youtube.yaml"),

    "Google": createRuleProvider("google.yaml"),

    "GitHub": createRuleProvider("github.yaml"),

    "Netflix": createRuleProvider("netflix.yaml"),

    "Spotify": createRuleProvider("spotify.yaml"),

    "Steam": createRuleProvider("steam.yaml"),

    "Telegram": createRuleProvider("telegram.yaml"),

    "TikTok": createRuleProvider("tiktok.yaml"),

    "Apple": createRuleProvider("apple.yaml"),

    "Microsoft": createRuleProvider("microsoft.yaml"),

    "NetworkTest": createRuleProvider("network-test.yaml")

  };


  // ================================================================
  // 10. Region detection & Region groups
  // ================================================================

  var regionPatterns = {

    "香港": [/香港/i, /\bHK\b/i, /HKG/i, /Hong\s*Kong/i, /HongKong/i],

    "台湾": [/台湾/i, /台灣/i, /\bTW\b/i, /TPE/i, /KHH/i, /TSA/i, /Taiwan/i, /Taipei/i],

    "日本": [/日本/i, /\bJP\b/i, /NRT/i, /HND/i, /KIX/i, /CTS/i, /FUK/i, /Japan/i, /Tokyo/i, /Osaka/i],

    "新加坡": [/新加坡/i, /\bSG\b/i, /SIN/i, /XSP/i, /Singapore/i],

    "韩国": [/韩国/i, /韓國/i, /\bKR\b/i, /ICN/i, /GMP/i, /PUS/i, /Korea/i, /Seoul/i],

    "美国": [/美国/i, /\bUS\b/i, /\bUSA\b/i, /LAX/i, /SFO/i, /JFK/i, /SJC/i, /United\s*States/i, /America/i],

    "加拿大": [/加拿大/i, /Canada/i, /Toronto/i, /Vancouver/i],

    "英国": [/英国/i, /UK/i, /United\s*Kingdom/i, /England/i, /London/i]

  };


  function detectRegion(proxyName) {

    for (var region in regionPatterns) {

      if (!Object.prototype.hasOwnProperty.call(regionPatterns, region)) continue;

      var patterns = regionPatterns[region];

      for (var i = 0; i < patterns.length; i++) {

        if (patterns[i].test(proxyName)) return region;

      }

    }

    return "其他地区";

  }


  var regionNodes = { "香港": [], "台湾": [], "日本": [], "新加坡": [], "韩国": [], "美国": [], "加拿大": [], "英国": [], "其他地区": [] };


  originalProxies.forEach(function(proxy) {

    if (!proxy || !proxy.name) return;

    var region = detectRegion(String(proxy.name));

    regionNodes[region].push(proxy.name);

  });


  var regionOrder = ["香港", "台湾", "日本", "新加坡", "韩国", "美国", "加拿大", "英国", "其他地区"];

  var regionGroups = [];


  regionOrder.forEach(function(region) {

    var nodes = regionNodes[region];

    if (!nodes || nodes.length === 0) return;

    var group = {

      "name": region,

      "type": "url-test",

      "proxies": nodes,

      "url": "https://www.gstatic.com/generate_204",

      "interval": 300,

      "timeout": 5000,

      "tolerance": 50,

      "lazy": true,

      "max-failed-times": 3,

      "expected-status": 204

    };

    var icon = getGroupIcon(region);

    if (icon) group["icon"] = icon;

    regionGroups.push(group);

  });


  var availableRegions = regionGroups.map(function(group) { return group.name; });


  // ================================================================
  // 11. Strategy Groups Definition
  // ================================================================

  // 1) 节点选择 (包含所有具体节点，供手动点选)
  var nodeSelectorGroup = {

    "name": "节点选择",

    "type": "select",

    "proxies": proxyNames.slice()

  };

  var iconNodeSelect = getGroupIcon("节点选择");

  if (iconNodeSelect) nodeSelectorGroup["icon"] = iconNodeSelect;


  // 2) 自动选择 (全部节点的 url-test 自动测速选优)
  var autoSelectGroup = {

    "name": "自动选择",

    "type": "url-test",

    "proxies": proxyNames.slice(),

    "url": "https://www.gstatic.com/generate_204",

    "interval": 300,

    "timeout": 5000,

    "tolerance": 50,

    "lazy": true,

    "max-failed-times": 3,

    "expected-status": 204

  };

  var iconAuto = getGroupIcon("自动选择");

  if (iconAuto) autoSelectGroup["icon"] = iconAuto;


  // 3) 国内直连
  var domesticDirectGroup = {

    "name": "国内直连",

    "type": "select",

    "proxies": ["DIRECT"]

  };

  var domesticIcon = getGroupIcon("国内直连");

  if (domesticIcon) domesticDirectGroup["icon"] = domesticIcon;


  // 4) 漏网之鱼 (未匹配规则时的兜底组)
  var finalMatchGroup = {

    "name": "漏网之鱼",

    "type": "select",

    "proxies": ["节点选择", "自动选择"].concat(availableRegions).concat(["国内直连"])

  };

  var iconFinal = getGroupIcon("漏网之鱼");

  if (iconFinal) finalMatchGroup["icon"] = iconFinal;


  // 5) 一键代理 (业务全局代理)
  var mainSelector = {

    "name": "一键代理",

    "type": "select",

    "proxies": proxyNames.concat(availableRegions).concat(["国内直连"])

  };

  var mainIcon = getGroupIcon("一键代理");

  if (mainIcon) mainSelector["icon"] = mainIcon;


  // 6) 业务分流策略组 (AI、YouTube等：内部显示所有节点 + 各国家自动筛选组 + 国内直连)
  function createBusinessGroup(name) {

    var group = {

      "name": name,

      "type": "select",

      "proxies": proxyNames.concat(availableRegions).concat(["国内直连"])

    };

    var icon = getGroupIcon(name);

    if (icon) group["icon"] = icon;

    return group;

  }


  var businessGroups = [

    createBusinessGroup("AI"),

    createBusinessGroup("YouTube"),

    createBusinessGroup("Google"),

    createBusinessGroup("GitHub"),

    createBusinessGroup("Netflix"),

    createBusinessGroup("Spotify"),

    createBusinessGroup("Steam"),

    createBusinessGroup("Telegram"),

    createBusinessGroup("TikTok"),

    createBusinessGroup("Apple"),

    createBusinessGroup("Microsoft")

  ];


  // 7) 网络检测组
  var networkTestGroup = {

    "name": "网络检测",

    "type": "select",

    "proxies": ["节点选择", "自动选择"]

  };

  var networkTestIcon = getGroupIcon("网络检测");

  if (networkTestIcon) networkTestGroup["icon"] = networkTestIcon;


  // ================================================================
  // 12. Assemble final proxy-groups
  // ================================================================

  config["proxy-groups"] =

    [

      nodeSelectorGroup,

      autoSelectGroup,

      finalMatchGroup

    ]

      .concat(businessGroups)

      .concat([networkTestGroup])

      .concat(regionGroups)

      .concat([domesticDirectGroup, mainSelector]);


  // ================================================================
  // 13. Routing rules
  // ================================================================

  config["rules"] = [

    "DOMAIN-SUFFIX,lan,DIRECT",

    "DOMAIN-SUFFIX,local,DIRECT",

    "DOMAIN-SUFFIX,localhost,DIRECT",

    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",

    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",

    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",

    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",

    "RULE-SET,NetworkTest,网络检测",

    "RULE-SET,AI,AI",

    "RULE-SET,YouTube,YouTube",

    "RULE-SET,Google,Google",

    "RULE-SET,GitHub,GitHub",

    "RULE-SET,Netflix,Netflix",

    "RULE-SET,Spotify,Spotify",

    "RULE-SET,Steam,Steam",

    "RULE-SET,Telegram,Telegram",

    "RULE-SET,TikTok,TikTok",

    "RULE-SET,Apple,Apple",

    "RULE-SET,Microsoft,Microsoft",

    "GEOSITE,private,国内直连",

    "GEOIP,private,国内直连,no-resolve",

    "GEOSITE,cn,国内直连",

    "GEOIP,cn,国内直连,no-resolve",

    // 默认兜底走漏网之鱼
    "MATCH,漏网之鱼"

  ];


  return config;

}
