#!/usr/bin/env ruby
# encoding: utf-8
#
# 自动订阅流水线：抓上游节点池 -> 合并去重 -> 用临时 mihomo 实例做健康检查
#                 -> 只把存活节点写成 Clash 订阅 -> 推到 GitHub 仓库
#
# 不重造上游的抓取层（dongchengjie/airport 是 92 个源 / 281 条 URL，其中 11 个源还要跑
# 自定义 JS 提取函数），只重造它的测速层：上游在 GitHub Actions 内网测速，与真实出口不一致。
#
# 依赖：ruby（含 psych，OpenClash 本地节点筛选本身就依赖它）+ mihomo 内核
# 用法：autosub.rb [-c sources.yaml] [--stage all|fetch|test|emit|push] [--dry-run]

require 'yaml'
require 'net/http'
require 'net/https'
require 'openssl'
require 'uri'
require 'json'
require 'base64'
require 'digest/md5'
require 'fileutils'
require 'tmpdir'
require 'socket'
require 'time'
require 'optparse'

FETCH_DEFAULTS = { 'cache_ttl' => 300, 'retries' => 3, 'tls_max_version' => nil }.freeze
HC_DEFAULTS = {
  'enabled' => true, 'rounds' => 2, 'confirm_rounds' => 2,
  'timeout_ms' => 4000, 'confirm_timeout_ms' => 8000,
  'concurrency' => 8, 'max_candidates' => 800,
  # 靶子会经本地解析器变成 IP 再交给远端节点去连，所以必须是「全球解析答案一致」的地址：
  # gstatic 在 223.5.5.5 下解出 120.253.253.226（Google 北京），境外节点连它必超时；
  # cp.cloudflare.com 国内国外都回 104.16.132.229 任播，哪里都通。
  'test_url' => 'http://cp.cloudflare.com/generate_204',
  'mihomo_bin' => nil, 'boot_wait' => 20
}.freeze
OUT_DEFAULTS = {
  'path' => 'autosub.yaml', 'stats' => 'stats.csv',
  'alive_list' => 'previous_alive.txt', 'manifest' => 'latest.json', 'min_alive' => 5,
  # 不测速时的输出上限，0 为不限。见 main 里的截断逻辑。
  'max_nodes' => 0,
  # 关掉就不发 rule-providers 和 🤖 AI 专用 组，规则退回纯 GEOSITE/GEOIP（离线也能用）。
  'rule_providers' => true
}.freeze
PUSH_DEFAULTS = {
  'method' => 'api', 'repo' => '', 'branch' => 'main',
  'token_env' => 'GITHUB_TOKEN', 'token_file' => nil,
  'files' => [{ 'local' => 'autosub.yaml', 'remote' => 'sub/autosub.yaml' }]
}.freeze
CORE_PATHS = %w[
  /etc/openclash/core/clash_meta /etc/openclash/clash /etc/openclash/mihomo
  /usr/bin/mihomo /usr/bin/mihomo-alpha /usr/bin/clash-meta /usr/bin/clash
  /usr/local/bin/mihomo /usr/share/openclash/mihomo
].freeze
# 2026-11-21 实测（221 节点，真实出口）：wireguard 29% 存活、http 4%、vless 2%、其余全灭。
# 想按协议收敛就填 type_allowlist，注意 OpenClash 的 keyword 只能匹配节点名字、匹配不到协议。
LINK_SCHEMES = %w[ss vmess vless trojan hysteria2].freeze
UNUSUAL_TYPES = %w[mieru tuic ssr anytls].freeze

def log(msg)
  $stdout.puts "[#{Time.now.strftime('%H:%M:%S')}] #{msg}"
  $stdout.flush
end

# psych 在不同 Ruby 版本里对 emoji 的转义行为不一致（Ruby 2.6 会输出 "\U0001F1EB"，3.x 输出字面量）。
# 节点名必须在「节点定义」和「分组引用」两处写法完全一致，否则 mihomo 认不出节点，
# 所以这里自己做引号，不依赖 YAML.dump。
def q(s)
  s = s.to_s
  return "''" if s.empty?
  risky = s =~ /\A[\s\-?:,\[\]{}#&*!|>'"%@`]/ ||
          s =~ /\s\z/ || s =~ /:(\s|\z)/ || s.include?('#') ||
          %w[true false null yes no on off ~].include?(s.downcase) ||
          s =~ /\A[+-]?(\d+(\.\d*)?|\.\d+)(e[+-]?\d+)?\z/i
  risky ? "'" + s.gsub("'", "''") + "'" : s
end

# ---------------- 抓取 ----------------

def cache_path(work, url)
  File.join(work, 'cache', Digest::MD5.hexdigest(url) + '.txt')
end

# TLS 降级重试。本机实测：OpenSSL 3.0.22 走 TLS1.3 握手会被掐断
# （unexpected eof while reading），同一地址锁 TLS1.2 一次就 200。
# 原因未定位（怀疑 1.3 的 ClientHello 分片经 mihomo 转发被丢），但降级是确定有效的。
# 第一次失败后把上限钉死在 1.2，后续请求不再重复撞墙。
$tls_max = nil

def tls_http(uri, open_timeout, read_timeout)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = uri.scheme == 'https'
  http.open_timeout = open_timeout
  http.read_timeout = read_timeout
  http.max_version = $tls_max if $tls_max && http.use_ssl?
  return http.start { |h| yield h }
rescue OpenSSL::SSL::SSLError => e
  raise if !http.use_ssl? || $tls_max
  log "  TLS 握手失败（#{e.message.to_s[0, 60]}），改用 TLS1.2 重试"
  $tls_max = OpenSSL::SSL::TLS1_2_VERSION
  retry
end

def http_get(url)
  if url =~ %r{^file://}
    path = url.sub(%r{^file://}, '')
    raise "本地文件不存在: #{path}" unless File.exist?(path)
    return File.binread(path).force_encoding('UTF-8')
  end
  seen = 0
  cur = url
  while seen < 6
    seen += 1
    uri = URI(cur)
    res = tls_http(uri, 30, 120) do |h|
      r = Net::HTTP::Get.new(uri)
      r['User-Agent'] = 'clash-verge/v2.4.5'
      r['Accept-Encoding'] = 'identity'
      h.request(r)
    end
    if res.is_a?(Net::HTTPSuccess)
      return res.body.to_s.dup.force_encoding('UTF-8')
    elsif res.is_a?(Net::HTTPRedirection)
      cur = res['location']
      cur = URI.join(uri, cur).to_s if cur !~ %r{^https?://}
    else
      raise "HTTP #{res.code}"
    end
  end
  raise '重定向次数过多'
end

def fetch_one(spec, work, fcfg)
  urls = [spec['url']].concat(Array(spec['mirrors'])).compact.reject(&:empty?)
  urls.each_with_index do |url, i|
    cp = cache_path(work, url)
    if File.exist?(cp) && (Time.now - File.mtime(cp)) < fcfg['cache_ttl'].to_i
      log "  #{spec['name']}: 命中缓存 #{File.basename(cp)}"
      return [url, File.binread(cp).force_encoding('UTF-8')]
    end
    tries = 0
    last = nil
    while tries < fcfg['retries'].to_i
      tries += 1
      begin
        body = http_get(url)
      rescue => e
        body = nil
        last = "#{e.class}: #{e.message.to_s[0, 50]}"
        log "  #{spec['name']}: 第#{tries}次失败 #{last}"
      end
      if body
        if body.bytesize > 400 && body.valid_encoding?
          FileUtils.mkdir_p(File.dirname(cp))
          File.binwrite(cp, body)
          log "  #{spec['name']}: #{i.zero? ? '主地址' : "镜像#{i}"} 拿到 #{body.bytesize} B"
          return [url, body]
        end
        log "  #{spec['name']}: 响应只有 #{body.bytesize} B 或编码不完整，换下一个地址"
        break
      end
      sleep 2
    end
  end
  [nil, nil]
end

# ---------------- 解析 ----------------

def looks_b64?(t)
  return false if t.length < 300 || t =~ /proxies\s*:/i
  core = t.gsub(/\s/, '')
  !!(core =~ %r{\A[A-Za-z0-9+\/=]+\z} && core.length % 4 == 0)
end

def link_to_proxy(line, src)
  line = line.strip
  m = line.match(%r{\A([A-Za-z0-9]+)://(.*)\z})
  return nil unless m
  scheme = m[1].downcase
  return nil unless LINK_SCHEMES.include?(scheme)
  rest = m[2]
  name = nil
  if rest.include?('#')
    head, frag = rest.split('#', 2)
    name = URI.decode_www_form_component(frag.to_s.split('&').first.to_s)
  else
    head = rest
  end
  p = nil
  begin
    case scheme
    when 'vmess'
      j = JSON.parse(Base64.decode64(head))
      p = { 'name' => j['ps'], 'type' => 'vmess', 'server' => j['add'], 'port' => j['port'].to_i,
            'uuid' => j['id'], 'alterId' => (j['aid'] || 0).to_i, 'cipher' => 'auto' }
      p['tls'] = true if j['tls'].to_s == 'tls'
      p['servername'] = j['sni'] if j['sni'].to_s != ''
      p['network'] = j['net'] if j['net'].to_s != '' && j['net'] != 'tcp'
      if j['net'] == 'ws'
        p['ws-opts'] = { 'path' => (j['path'].to_s == '' ? '/' : j['path']),
                         'headers' => { 'Host' => j['host'].to_s } }
      end
    when 'vless', 'trojan', 'hysteria2'
      hostpart, query = head.split('?', 2)
      cred, srv = hostpart.split('@', 2)
      return nil unless srv
      server, port = srv.split(':')
      qh = query ? Hash[URI.decode_www_form(query)] : {}
      if scheme == 'vless'
        p = { 'type' => 'vless', 'server' => server, 'port' => port.to_i, 'uuid' => cred, 'udp' => true }
        p['tls'] = true if %w[tls reality].include?(qh['security'].to_s)
        p['servername'] = qh['sni'] if qh['sni']
        p['network'] = qh['type'] if qh['type'] && qh['type'] != 'tcp'
        p['flow'] = qh['flow'] if qh['flow'].to_s != ''
        if qh['security'] == 'reality'
          p['reality-opts'] = { 'public-key' => qh['pbk'], 'short-id' => qh['sid'].to_s }
          p['client-fingerprint'] = qh['fp'] || 'chrome'
        end
        p['ws-opts'] = { 'path' => qh['path'] || '/', 'headers' => { 'Host' => qh['host'].to_s } } if qh['type'] == 'ws'
      else
        key = scheme == 'trojan' ? 'password' : 'password'
        p = { 'type' => scheme, 'server' => server, 'port' => port.to_i,
              key => URI.decode_www_form_component(cred.to_s) }
        p['sni'] = qh['sni'] if qh['sni']
        p['skip-cert-verify'] = true if %w[1 true].include?((qh['allowInsecure'] || qh['insecure']).to_s)
        p['alpn'] = qh['alpn'].split(',') if qh['alpn']
      end
    when 'ss'
      hostpart, query = head.split('?', 2)
      qh = query ? Hash[URI.decode_www_form(query)] : {}
      method = password = server = nil
      if hostpart.include?('@')
        cred, srv = hostpart.split('@', 2)
        cred = Base64.decode64(cred) if cred =~ %r{\A[A-Za-z0-9+\/=]+\z} && !cred.include?(':')
        method, password = cred.split(':', 2)
        server = srv
      else
        dec = Base64.decode64(hostpart)
        if dec =~ /@/
          cred, server = dec.split('@', 2)
          method, password = cred.split(':', 2)
        else
          method, password, server = hostpart.split(':')
        end
      end
      server = server.to_s.split('/').last
      host, port = server.rindex(':') ? [server[0...server.rindex(':')], server[server.rindex(':') + 1..-1]] : [nil, nil]
      p = { 'type' => 'ss', 'server' => host, 'port' => port.to_i, 'cipher' => method, 'password' => password }
      pl = qh['plugin'].to_s
      if pl =~ /^(obfs-local|v2ray-plugin)/
        p['plugin'] = pl.split('?').first
        p['plugin-opts'] = Hash[URI.decode_www_form(pl.split('?', 2)[1].to_s.tr(';', '&'))] if pl.include?('?')
      end
    end
  rescue => e
    return nil
  end
  return nil unless p && p['server'].to_s =~ /\A[\w.\-:]+\z/ && p['port'].to_i > 0
  p['name'] = name.to_s.empty? ? "#{p['type'].upcase}-#{p['server']}:#{p['port']}" : name
  p['__src'] = src
  p
end

def parse_content(text, src)
  out = []
  skipped = 0
  t = text.to_s
  if t =~ /proxies\s*:/i && t !~ %r{\A\s*[A-Za-z0-9+/=\s]+\z}
    begin
      c = YAML.load(t)
      Array(c.is_a?(Hash) ? c['proxies'] : nil).each do |x|
        next unless x.is_a?(Hash) && x['name'] && x['server'] && x['port']
        h = x.dup
        h['__src'] = src
        out << h
      end
    rescue => e
      log "  #{src}: YAML 解析失败 #{e.class} #{e.message.to_s[0, 60]}"
    end
  else
    body = looks_b64?(t) ? Base64.decode64(t) : t
    body.to_s.each_line do |line|
      line = line.strip
      next if line.empty?
      if line =~ %r{\A[A-Za-z0-9]+://}
        pr = link_to_proxy(line, src)
        pr ? out.push(pr) : skipped += 1
      end
    end
  end
  [out, skipped]
end

# ---------------- 合并 ----------------

def sig(p)
  key = case p['type'].to_s.downcase
        when 'vmess', 'vless' then p['uuid'].to_s
        when 'trojan', 'hysteria2' then p['password'].to_s
        when 'ss' then "#{p['cipher']}:#{p['password']}"
        when 'wireguard' then p['private-key'].to_s
        when 'socks5', 'http', 'snell' then "#{p['username']}:#{p['password']}"
        else ''
        end
  [p['type'].to_s.downcase, p['server'].to_s.downcase, p['port'].to_s, key].join('|')
end

def dedupe(all)
  hits = {}
  uniq = []
  all.each do |p|
    s = sig(p)
    if hits.key?(s)
      hits[s] += 1
    else
      hits[s] = 1
      p['__hits'] = 1
      uniq << p
    end
  end
  uniq.each { |p| p['__hits'] = hits[sig(p)] }
  uniq
end

def uniq_names!(list)
  used = {}
  list.each do |p|
    n = p['name'].to_s
    n = "node-#{p['server']}:#{p['port']}" if n.empty?
    if used[n]
      used[n] += 1
      n2 = "#{n} ##{used[n]}"
      p['name'] = n2
      used[n2] = 1
    else
      used[n] = 1
    end
  end
  list
end

# ---------------- 测速 ----------------

def find_core(cfg)
  cands = [cfg['mihomo_bin'], ENV['MIHOMO_BIN']].flatten.compact.reject { |s| s.to_s.empty? }
  cands += CORE_PATHS
  %w[mihomo mihomo-alpha clash-meta clash].each { |n| w = `which #{n} 2>/dev/null`.strip; cands << w unless w.empty? }
  # OpenClash 的内核文件名各家不一样（clash / clash_meta / mihomo-linux-arm64-xxx），兜底扫目录
  cands.concat(Dir.glob('/etc/openclash/core/*') + Dir.glob('/etc/openclash/*meta*'))
  hit = cands.uniq.find { |p| File.executable?(p.to_s) && !File.directory?(p.to_s) }
  return nil unless hit
  ver = begin
    IO.popen([hit, '-v'], err: %i[child out], &:read).to_s.lines.first.to_s.strip
  rescue StandardError
    ''
  end
  log "内核 #{hit}#{ver.empty? ? '' : "（#{ver}）"}"
  log '  警告：这个文件看起来不是 mihomo/Clash Meta 内核，请核对 healthcheck.mihomo_bin' unless ver =~ /mihomo|meta|clash|proxy/i
  hit
end

def free_port
  s = Socket.new(:INET, :STREAM)
  s.bind(Addrinfo.tcp('127.0.0.1', 0))
  port = s.local_address.ip_port
  s.close
  port
end

def api_get(port, path, query = nil, secret = nil, rd = 10)
  uri = URI("http://127.0.0.1:#{port}#{path}")
  uri.query = query if query
  req = Net::HTTP::Get.new(uri)
  req['Authorization'] = "Bearer #{secret}" if secret
  Net::HTTP.start('127.0.0.1', port, :open_timeout => 3, :read_timeout => rd) { |h| h.request(req) }
end

# 节点名要放进 URL 路径段，不能直接用 encode_www_form_component：那是表单编码，
# 空格转成 + ，而 mihomo(Go) 只把 %20 解成空格、+ 原样保留。全部 1614 个节点名都带空格，
# 于是查的是「🇭🇰+香港-xxx」这种不存在的名字 -> 每个都 HTTP 404。补一步换成 %20 即可。
def path_esc(s)
  URI.encode_www_form_component(s.to_s).gsub('+', '%20')
end

$err_mu = Mutex.new
$err_raw = []

# 内核在 503/504 的 body 里给了真实原因（连的是哪个 IP、超时还是拒绝）。
# 之前只留状态码，等于把「fake-ip 被当目标地址」这类根因直接扔了。
# 分桶时把数字折成 N，否则 1052 个节点会散成 1052 个桶，分布就没法看了。
def err_bucket(code, body)
  m = begin
        JSON.parse(body.to_s)['message'].to_s
      rescue
        body.to_s
      end
  m = m.strip.gsub(/\s+/, ' ')
  k = m.gsub(/\d+/, 'N')[0, 40]
  k = "HTTP#{code}" if k.empty?
  $err_mu.synchronize { $err_raw << "HTTP#{code} #{m[0, 120]}" if $err_raw.size < 4000 }
  # 用空格而不是 |：errs 本身拿 | 拼各轮结果，键里再混一个 | 就分不清是轮次分隔还是消息内容。
  "HTTP#{code} #{k}"
end

def probe_one(port, secret, name, timeout_ms, test_url)
  res = api_get(port, "/proxies/#{path_esc(name)}/delay",
                URI.encode_www_form('url' => test_url, 'timeout' => timeout_ms),
                secret, (timeout_ms / 1000) + 8)
  return (JSON.parse(res.body.to_s)['delay'] rescue 'badjson') if res.code.to_i == 200
  err_bucket(res.code.to_i, res.body)
rescue => e
  e.is_a?(Timeout::Error) ? 'timeout' : 'abort'
end

def probe_round(names, port, secret, timeout_ms, conc, test_url)
  queue = Queue.new
  names.each { |n| queue << n }
  out = {}
  mu = Mutex.new
  workers = Array.new([conc, names.size].min) do
    Thread.new do
      loop do
        n = begin
              queue.pop(true)
            rescue ThreadError
              nil
            end
        break unless n
        ms = probe_one(port, secret, n, timeout_ms, test_url)
        mu.synchronize { out[n] = ms }
      end
    end
  end
  workers.each(&:join)
  out
end

# 上游聚合站的链接数据有脏字段，会让 mihomo 整份配置解析失败（一个节点废 1052 个）。
# 实测 2026-11-21：106 个节点的 reality short-id 不是 16 位 hex（如 "0e40"、"16"），
# 52 个节点的 reality-opts 里混进了爬虫留下的 _spider-x 键。
# short-id 不合规就置空而不是丢弃：服务器不校验 shortId 时节点仍然可用，
# 真连不上也会由测速淘汰，等于把判断权交给实测而不是猜。
def sanitize!(list)
  n = 0
  list.each do |p|
    ro = p['reality-opts']
    next unless ro.is_a?(Hash)
    sid = ro['short-id'].to_s
    unless sid == '' || sid =~ /\A[0-9a-fA-F]{16}\z/
      ro['short-id'] = ''
      n += 1
    end
    extra = ro.keys.map(&:to_s) - %w[public-key short-id]
    extra.each { |k| ro.delete(k); ro.delete(k.to_sym) }
    n += 1 unless extra.empty?
  end
  n
end

# 有一类节点的问题是「让内核整份拒绝」而不是「连不上」：mihomo 解析代理是全有全无的，
# 一个非法字段就让它拒绝加载整份配置——OpenClash 的表现是「配置文件下载成功、测试失败」，
# 一个节点都出不来。实测 v1.19.34 报：
#   proxy 19: ss 27.124.5.86:8388 cipher: 2022-blake3-aes-256-gcm
#   initialize error: decode key: illegal base64 data at input byte 43
# 2022-blake3 系列的 password 不是任意口令，是定长 base64 密钥：aes-128 解出来必须 16 字节、
# aes-256 必须 32 字节。坏的就是口令本身，改字段救不回来，只能删。
def drop_broken!(list)
  dropped = []
  list.reject! do |p|
    next false unless p['type'].to_s == 'ss'
    m = p['cipher'].to_s.match(/2022-blake3-aes-(128|256)-gcm/)
    next false unless m
    want = m[1] == '128' ? 16 : 32
    raw = begin
      Base64.strict_decode64(p['password'].to_s)
    rescue ArgumentError
      nil
    end
    next false if raw && raw.bytesize == want
    dropped << "#{p['name']}（#{p['cipher']} 的口令不是 #{want} 字节的 base64）"
    true
  end
  dropped
end

# 内核点名拒绝某个节点时返回 [0 基下标, 原因]。实测 msg 里的编号是 0 基。
def core_reject(logfile)
  return nil unless File.exist?(logfile)
  line = File.readlines(logfile).reverse.find { |l| l =~ /Parse config error: proxy (\d+): ([^"]*)"/ }
  return nil unless line
  [$1.to_i, $2.to_s.strip]
rescue
  nil
end

# 用 Addrinfo 而不是 Resolv：前者是 libc 解析器，和内核实际走的同一条路，
# 也不用往路由器上再装 ruby-resolv。
# 这里查的是「本机解析测试地址/节点域名拿到的是什么 IP」。OpenClash 开 fake-ip 时
# 本地 dnsmasq 会回 198.18.0.0/16，那种地址远端节点根本连不到，测速会全灭——
# 表现和「节点都死了」一模一样，所以必须单独看一眼再下结论。
def dns_note(list, urls)
  fake = 0
  ips = 0
  dom = 0
  fail = 0
  Array(list).first(40).each do |p|
    s = p['server'].to_s
    next if s.empty?
    if s =~ /\A\d{1,3}(?:\.\d{1,3}){3}\z/ || s.include?(':')
      ips += 1
      next
    end
    dom += 1
    begin
      a = Addrinfo.getaddrinfo(s, 80, nil, :STREAM).first&.ip_address
      fake += 1 if a.to_s.start_with?('198.18.', '198.19.')
    rescue
      fail += 1
    end
  end
  Array(urls).each do |u|
    th = begin
           URI(u.to_s).host.to_s
         rescue
           ''
         end
    tr = if th.empty?
           '测试地址里没有主机名'
         else
           begin
             Addrinfo.getaddrinfo(th, 80, nil, :STREAM).map(&:ip_address).uniq.join(',')
           rescue => e
             "解析失败 #{e.class}"
           end
         end
    log "  系统解析自检（走 libc，不含临时实例自己那份）：#{th} -> #{tr}"
  end
  log "  系统解析自检：抽样 #{ips + dom} 个 server，IP 直连 #{ips}、域名 #{dom}（fake-ip #{fake}、解不出 #{fail}）"
rescue => e
  log "  解析自检未完成（#{e.class}）"
end

def healthcheck(list, hc)
  bin = find_core(hc)
  raise '找不到 mihomo 内核：请设置 healthcheck.mihomo_bin，或确认 PATH 里有 mihomo' unless bin

  cur = list
  last_err = nil
  parse_drops = 0
  tried_unusual = false
  # 本机 resolv.conf 指向 127.0.0.1 的 dnsmasq，OpenClash 的 fake-ip 会回 198.18.0.127（实测）。
  # 测速时内核把这个假地址交给远端节点去连，节点在自家机房连 RFC2544 保留段必然黑洞，
  # 于是 1052 个节点不管死活一起超时——那个 0% 就是这么来的。所以临时实例自带解析器，
  # 实测 223.5.5.5 直连能拿到真 IP（120.253.253.226）。若 OpenClash 连出站 53 也劫持，
  # 下面那行 fake-ip 提示和失败样本会立刻暴露，届时填 healthcheck.nameserver: false 或换测速目标。
  sys_fake = nil
  begin
    Array(hc['test_url']).each do |u|
      h = begin
            URI(u.to_s).host.to_s
          rescue
            ''
          end
      next if h.empty?
      a = begin
            Addrinfo.getaddrinfo(h, 80, nil, :STREAM).first&.ip_address.to_s
          rescue
            nil
          end
      if a.to_s.start_with?('198.18.', '198.19.')
        sys_fake = "#{h}=#{a}"
        break
      end
    end
  rescue
    nil
  end
  ns = hc.key?('nameserver') ? hc['nameserver'] : '223.5.5.5'
  dns_conf = nil
  # 临时实例的 rules 只有 MATCH,HC，而 dns.proxy-mode 默认按规则派发——
  # 那连发往 DNS 服务器本身的查询都会被塞给某个（大概率是死的）节点，解析跟着一起死。
  # 所以给每个 nameserver 单独开一条 DIRECT，解析必须走路由器自己的出口。
  hc_rules = ['MATCH,HC']
  if ns == false
    log '  DNS：跟随系统（healthcheck.nameserver: false）'
  else
    dns_conf = { 'enable' => true, 'listen' => "127.0.0.1:#{free_port}", 'default-nameserver' => Array(ns),
                'nameserver' => Array(ns), 'proxy-server-nameserver' => Array(ns), 'proxy-mode' => 'rule',
                'enhanced-mode' => 'redir-host', 'ipv6' => false }
    hc_rules = Array(ns).select { |s| s =~ /\A(\d{1,3}\.){3}\d{1,3}\z/ }
                        .map { |s| "IP-CIDR,#{s}/32,DIRECT,no-resolve" }.concat(hc_rules)
    log "  DNS：临时实例自带解析 #{Array(ns).join('/')} 并强制 DIRECT" \
        "#{sys_fake ? "（系统那套给的是 fake-ip #{sys_fake}）" : ''}；53 若仍被劫持，下面的失败样本会现出 198.18.x 的靶地址"
  end
  loop do
    res = nil
    begin
      Dir.mktmpdir('autosub') do |dir|
        port = free_port
        mix = free_port
        secret = Array.new(16) { rand(36).to_s(36) }.join
        conf = {
          'mixed-port' => mix, 'allow-lan' => false, 'log-level' => 'warning', 'mode' => 'rule',
          'external-controller' => "127.0.0.1:#{port}", 'secret' => secret,
          'proxies' => cur.map { |p| p.reject { |k, _| k.to_s.start_with?('__') } },
          'proxy-groups' => [{ 'name' => 'HC', 'type' => 'select', 'proxies' => ['DIRECT'] + cur.map { |p| p['name'] } }],
          'rules' => hc_rules
        }
        conf['dns'] = dns_conf if dns_conf
        File.binwrite(File.join(dir, 'config.yaml'),
                      conf.to_yaml.gsub(/(?<!\\)\\U([0-9A-Fa-f]{8})/) { [$1.to_i(16)].pack('U') })
        log "临时实例 127.0.0.1:#{port}（混合端口 #{mix}，节点 #{cur.size}，不建 tun、不碰 OpenClash）"
        errlog = File.join(dir, 'core.log')
        # 不能用 IO.popen：读模式下它自己占住 fd 1，再传 :out 就是「fd 1 specified twice」。
        # 我们不需要读内核的 stdout（状态全走 controller API），只要把输出落到日志文件。
        pid = Process.spawn(bin, '-d', dir, :out => errlog, :err => [:child, :out])
        begin
          # 控制器设了 secret，mihomo 对每个路由都做鉴权：/version 不带 Authorization
          # 会一直 401。之前这里没传 secret，等于内核好着却永远「未响应」。
          up = false
          note = nil
          hc['boot_wait'].to_i.times do
            begin
              r = api_get(port, '/version', nil, secret)
              up = r.code.to_i == 200
              note = "HTTP #{r.code}" unless up
              break if up
            rescue => e
              note = e.class.to_s
            end
            sleep 1
          end
          unless up
            tcp = begin
                    TCPSocket.new('127.0.0.1', port).close
                    'TCP 连得上（说明在监听，是协议层问题）'
                  rescue => e
                    "TCP 连不上（#{e.class}，说明没监听）"
                  end
            raise "内核 #{hc['boot_wait']}s 内未通过 /version 探测：#{note}；#{tcp}"
          end

          names = cur.map { |p| p['name'] }
          # 预检：控制器看到的名字和本地对一遍。名字对不上时每个节点都只会回 404，
          # 光看失败分布分不清是链路死了还是寻址错了（实测被这个坑过一次）。
          begin
            r = api_get(port, '/proxies', nil, secret, 20)
            if r.code.to_i == 200
              got = JSON.parse(r.body.to_s).fetch('proxies', {}).keys
              hit = (names - got).size
              log "  控制器侧 #{got.size} 个，本地 #{names.size} 个对不上 #{hit} 个"
            else
              log "  控制器 /proxies 返回 HTTP #{r.code}"
            end
          rescue => e
            log "  控制器 /proxies 预检未完成（#{e.class}）"
          end
          urls = Array(hc['test_url']).map(&:to_s).reject(&:empty?)
          urls = [HC_DEFAULTS['test_url']] if urls.empty?
          urls.select! { |u| URI(u).host rescue nil }
          raise 'healthcheck.test_url 里没有能用的地址' if urls.empty?
          dns_note(cur, urls)
          coarse = []
          hc['rounds'].to_i.times do |i|
            u = urls[i % urls.size]
            log "  粗筛 第#{i + 1}/#{hc['rounds']}轮（#{hc['timeout_ms']}ms，并发 #{hc['concurrency']}，靶 #{URI(u).host}）"
            coarse << [u, probe_round(names, port, secret, hc['timeout_ms'].to_i, hc['concurrency'].to_i, u)]
            sleep 2
          end
          # 粗筛取并集。靶子自己可能从节点侧不可达：gstatic 在国内 DNS 解出来是 Google 北京
          # 机房的 IP，境外节点连它本来就超时，取交集就把这种结构性失败记成节点死亡。
          ok = ->(r, n) { r[n].is_a?(Numeric) && r[n] > 0 }
          passed = names.select { |n| coarse.any? { |_, r| ok.call(r, n) } }
          log "  至少一个靶子通过 #{passed.size}/#{names.size}" \
              "（#{(passed.size * 100.0 / [names.size, 1].max).round(1)}%）"
          if coarse.size > 1
            # 分靶统计：哪个靶子贡献了多少，决定它该留在列表里还是该换掉。
            log "  分靶通过：" + coarse.map { |u, r|
              "#{URI(u).host} #{r.count { |_, v| v.is_a?(Numeric) && v > 0 }}"
            }.join('  ')
          end
          conf = []
          if !passed.empty? && hc['confirm_rounds'].to_i > 0
            # 复查只认第一个靶。多个靶取交集实测会把 38 个候选砍到 16 个——那些节点连得上
            # Cloudflare 任播，只是连不到北京那个 gstatic，这是靶子的锅不是节点的锅。
            # 第一个靶写在 sources.yaml 最前面，粗筛和复查共用它。
            u = urls.first
            cand = passed
            hc['confirm_rounds'].to_i.times do |i|
              log "  复查 第#{i + 1}/#{hc['confirm_rounds']}轮（#{hc['confirm_timeout_ms']}ms，靶 #{URI(u).host}）"
              r = probe_round(passed, port, secret, hc['confirm_timeout_ms'].to_i, hc['concurrency'].to_i, u)
              conf << [u, r]
              # 单轮连通数决定怎么读那个交集：两轮各 30、31 取成交集 22 是抖动（节点时通时不通）；
              # 两轮都只有 22 出头，说明这 22 个就是稳定可用的一批，调超时没有意义。
              log "    本轮连通 #{r.count { |_, v| v.is_a?(Numeric) && v > 0 }}/#{passed.size}"
              sleep 2
            end
            # 复查跨轮取交集：每轮都要连上，抖动的和蹭运气的在这里筛掉。
            passed = passed.select { |n| conf.all? { |_, r| ok.call(r, n) } }
            log "  复查全过 #{passed.size}"
            # 淘汰原因单独打，不和粗筛混在一起：报 503 说明粗筛那下是撞运气（节点握手时好时坏），
            # 这刀该砍；报 504 说明卡在超时边界，是 confirm_timeout_ms 不够长，该调参而不是接受。
            lost = cand - passed
            ld = {}
            lost.each do |n|
              conf.map { |_, r| r[n] }.compact
                  .reject { |v| v.is_a?(Numeric) && v > 0 }
                  .map(&:to_s).uniq.each { |k| ld[k] = (ld[k] || 0) + 1 }
            end
            log "  复查淘汰 #{lost.size} 个：" +
                ld.sort_by { |_, v| -v }.map { |k, v| "#{k}x#{v}" }.join('  ') unless lost.empty?
          end
          alive_set = {}
          passed.each { |n| alive_set[n] = true }
          res = {}
          names.each do |n|
            # 复查轮只覆盖粗筛通过的节点，没被复查的名字在那些轮里没有记录，要跳过而不是当失败。
            vals = (coarse + conf).map { |_, r| r.key?(n) ? r[n] : nil }.compact
            nums = vals.select { |v| v.is_a?(Numeric) && v > 0 }
            res[n] = { 'rounds' => vals.size, 'ok' => nums.size,
                       'median' => nums.empty? ? nil : nums.sort[nums.size / 2],
                       'alive' => !alive_set[n].nil?,
                       'errs' => vals.reject { |v| v.is_a?(Numeric) && v > 0 }.map(&:to_s).uniq.join('; ') }
          end
        ensure
          begin
            Process.kill('TERM', pid)
            Process.wait(pid)
          rescue
            nil
          end
          if res.nil?
            tail = File.exist?(errlog) ? File.readlines(errlog).last(6).join : '(无日志)'
            log "  内核日志尾部:\n#{tail}"
            # 临时目录随 mktmpdir 一起没了，把全文留到 /tmp 好排查首次启动失败
            begin
              File.binwrite('/tmp/autosub-core.log', File.binread(errlog))
              log '  完整内核日志已存 /tmp/autosub-core.log'
            rescue
              nil
            end
          end
        end
      end
    rescue => e
      last_err = e
      log "  本轮测速异常 #{e.class}: #{e.message.to_s[0, 120]}"
    end
    return res, cur if res
    # 策略一：内核点名拒绝某个节点（上游数据脏），按它给的 0 基下标剔除后重试
    idx, why = core_reject('/tmp/autosub-core.log')
    bad = idx ? cur[idx] : nil
    if bad && parse_drops < 8
      parse_drops += 1
      log "  内核拒绝第 #{idx} 个节点 #{bad['name']}（#{why}）：剔除后重试（#{parse_drops}/8）"
      cur = cur - [bad]
      next
    end
    # 策略二：起不来又没点名，把非常规协议整体剔掉再试一轮
    drop = cur.select { |p| UNUSUAL_TYPES.include?(p['type'].to_s.downcase) }
    if !drop.empty? && !tried_unusual
      tried_unusual = true
      log "  剔除 #{drop.size} 个非常规协议节点（#{drop.map { |p| p['type'] }.uniq.join('/')}）后重试"
      cur = cur - drop
      next
    end
    raise "mihomo 临时实例未能完成测速#{last_err ? "：#{last_err.class} #{last_err.message.to_s[0, 120]}" : ''}"
  end
end

# ---------------- 产出 ----------------

RULES = [
  'GEOSITE,github,🚀 节点选择',
  'GEOSITE,twitter,🚀 节点选择',
  'GEOSITE,youtube,🚀 节点选择',
  'GEOSITE,google,🚀 节点选择',
  'GEOSITE,telegram,🚀 节点选择',
  'GEOSITE,netflix,🚀 节点选择',
  # apple 这个分类实测在 meta-rules-dat 的 GeoSite 里就有（GEOSITE,apple 直接可用），
  # 加它是因为 GEOSITE,CN 管不到 apple.com：更新、iCloud、推送这些走免费节点纯属浪费。
  'GEOSITE,apple,🎯 全局直连',
  'GEOSITE,bilibili,🎯 全局直连',
  'GEOSITE,CN,🎯 全局直连',
  'GEOIP,CN,🎯 全局直连',
  'MATCH,🐟 漏网之鱼'
].freeze

# 规则集不抄进订阅文件，运行时让内核自己从 jsDelivr 拉。为什么只留两条：
# 一是 meta-rules-dat 的 GeoSite 里 openai/apple/telegram/netflix/disney/google 这些分类全都有
# （实测 mihomo -t 逐个 Load GeoSite rule 成功），GEOSITE 零额外下载就够用了，
# provider 只有在「GeoSite 给不了」的地方才值得存在；
# 二是 blackmatrix7 的 Telegram/OpenAI 里带 IP-CIDR 和 IP-CIDR6 条目，而 GEOSITE 只按域名匹配，
# 直连 Telegram 服务器 IP、以及 ChatGPT 那几条 IP 段的流量它管不到——这才是这两条的增量。
# behavior 必须写 classical：这些文件里混了 DOMAIN-SUFFIX/IP-CIDR/PROCESS，
# 写成 domain 会让带 IP 的条目整条失效，而且不报错，是最难查的那种坏。
# 广告规则集不开：Advertising_Domain.yaml 实测 7.9 MB，路由器每 24h 拉一次不现实。
RULE_PROVIDERS = [
  ['telegram', 'Telegram', '🚀 节点选择'],
  ['openai', 'OpenAI', '🤖 AI 专用'],
].freeze
RP_BASE = 'https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash'.freeze

def rule_provider_lines
  out = ['rule-providers:']
  RULE_PROVIDERS.each do |key, name, _tgt|
    out << "  #{key}:"
    out << '    type: http'
    out << '    format: yaml'
    out << '    behavior: classical'
    out << "    url: \"#{RP_BASE}/#{name}/#{name}.yaml\""
    out << "    path: ./ruleset/#{key}.yaml"
    out << '    interval: 86400'
    # lazy：启动时不下载，第一次被规则命中才拉。开机少两个请求，
    # 代价是第一条命中 Telegram/OpenAI 的连接多等一次下载。
    out << '    lazy: true'
  end
  out
end

def proxy_block(p, st, carried = false)
  clean = p.reject { |k, _| k.to_s.start_with?('__') }
  y = clean.to_yaml.sub(/\A---\s*\n?/, '').chomp.split("\n")
  i = y.index { |l| l =~ /\Aname:/ }
  if i
    y[i] = "name: #{q(p['name'])}"
  else
    y.unshift("name: #{q(p['name'])}")
  end
  meta = "T=#{st['median'] ? st['median'].to_s + 'ms' : '-'} 通过=#{st['ok']}/#{st['rounds']} 命中#{p['__hits']}次 源=#{p['__src']}"
  meta += '｜上轮通过本轮未过，靠并集带过来' if carried
  ["  # #{meta}", "  - #{y.first}"] + y[1..-1].to_a.map { |l| "    #{l}" }
end

def build_yaml(list, stats, note, carry = nil, rp = true)
  s = ['# 自动订阅流水线生成，请勿手工编辑', "# #{note}",
       'mixed-port: 7890', 'allow-lan: true', 'ipv6: false', 'mode: rule',
       'log-level: info', 'unified-delay: true', 'tcp-concurrent: true',
       'external-controller: 127.0.0.1:9090', 'geodata-mode: true',
       'geox-url:',
       '  geoip: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"',
       '  geosite: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"',
       '  mmdb: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"',
       'profile:', '  store-selected: true', '  store-fake-ip: true',
       'dns:', '  enable: true', '  ipv6: false', '  enhanced-mode: fake-ip',
       '  fake-ip-range: 198.18.0.1/16',
       # 测速靶域名不能进 fake-ip 池：mihomo 自己的 url-test 也要解析它，拿到 198.18.x 就直接
       # 连这个假地址，全成超时——跟我们在路由器上踩的是同一个坑，只是换成配置里自发生效。
       '  fake-ip-filter:', '    - +.cp.cloudflare.com', '    - +.gstatic.com', '    - +.google.com',
       '  default-nameserver:', '    - 223.5.5.5',
       '    - 119.29.29.29', '  nameserver:', '    - https://doh.pub/dns-query',
       '    - https://dns.alidns.com/dns-query',
       # sniff 在 mihomo 是「协议 -> {ports: [...]}」的 map；老 Clash 那种 `- ".+"` 列表写法
       # 内核直接拒绝：yaml: cannot unmarshal !!seq into map[string]config.RawSniffingConfig。
       # OpenClash 添加订阅时的「配置文件测试」就是死在这一行，报「测试失败，请查看内核日志」。
       'sniffer:', '  enable: true', '  override-destination: true',
       '  sniff:',
       '    HTTP:', '      ports: [80, 8080-8888]',
       '    TLS:', '      ports: [443, 8443]',
       '    QUIC:', '      ports: [443, 8443]',
       '  force-domain:', '    - "+.google.com"', '    - "+.netflix.com"']
  s.concat(rule_provider_lines) if rp
  s << 'proxies:'
  list.each { |p| s.concat(proxy_block(p, stats[p['name']] || { 'rounds' => 0, 'ok' => 0, 'median' => nil },
                                       carry ? carry[p['name']] : false)) }
  # 这两个组必须带 url/interval，否则关掉流水线测速后没有任何东西在国内线上挑节点。
  # 靶子用 cp.cloudflare.com：国内外解析答案一致（任播 104.16.132.229），gstatic 在国内 DNS 下
  # 会解出 Google 北京机房 IP，境外节点连不上，测出来的延迟全是超时。
  hc_url = 'http://cp.cloudflare.com/generate_204'
  names = list.map { |p| p['name'] }
  s << 'proxy-groups:'
  s << '  - name: 🚀 节点选择'
  s << '    type: select'
  s << '    proxies:'
  (['♻️ 自动选择', '🚑 故障转移', '🎯 全局直连', 'DIRECT'] + names).each { |n| s << "      - #{q(n)}" }
  s << '  - name: ♻️ 自动选择'
  s << '    type: url-test'
  s << "    url: #{hc_url}"
  s << '    interval: 600'
  s << '    timeout: 5000'
  s << '    tolerance: 30'
  s << '    proxies:'
  names.each { |n| s << "      - #{q(n)}" }
  s << '  - name: 🚑 故障转移'
  s << '    type: fallback'
  s << "    url: #{hc_url}"
  s << '    interval: 600'
  s << '    timeout: 5000'
  s << '    proxies:'
  names.each { |n| s << "      - #{q(n)}" }
  s << '  - name: 🎯 全局直连'
  s << '    type: select'
  s << '    proxies:'
  s << '      - DIRECT'
  if rp
    # 成员只放分组引用，不复制 300 个节点名：抄一份就多 60 KB，
    # 而且内核会把同一批节点重复测一遍，选路质量不变、路由器更累。
    # 这个组的用处是「哪天找到一个能过 ChatGPT 的节点，就手动钉在这里」，不影响其他流量。
    s << '  - name: 🤖 AI 专用'
    s << '    type: select'
    s << '    proxies:'
    ['♻️ 自动选择', '🚑 故障转移', '🎯 全局直连', 'DIRECT'].each { |n| s << "      - #{q(n)}" }
  end
  s << '  - name: 🐟 漏网之鱼'
  s << '    type: select'
  s << '    proxies:'
  ['♻️ 自动选择', '🚀 节点选择', 'DIRECT'].each { |n| s << "      - #{q(n)}" }
  s << 'rules:'
  # RULE-SET 排在 GEOSITE 前面：同一批域名两条都能命中，先命中的生效，
  # 让带 IP 段的 provider 有机会把「不走域名、直接连 IP」的那部分也接住。
  rp_rules = rp ? RULE_PROVIDERS.map { |k, _n, tgt| "RULE-SET,#{k},#{tgt}" } : []
  (rp_rules + RULES).each { |r| s << "  - #{r}" }
  # psych 对非 BMP 字符（旗标 emoji）会输出 \U 转义，各 Ruby 版本行为不一致；统一还原成字面量
  s.join("\n").gsub(/(?<!\\)\\U([0-9A-Fa-f]{8})/) { [$1.to_i(16)].pack('U') } + "\n"
end

def build_csv(list, stats)
  rows = ['name,type,server,port,rounds,passed,median_ms,errors,hits,source']
  list.each do |p|
    st = stats[p['name']] || { 'rounds' => 0, 'ok' => 0, 'median' => nil, 'errs' => '' }
    cells = [p['name'], p['type'], p['server'], p['port'], st['rounds'], st['ok'], st['median'],
             st['errs'], p['__hits'], p['__src']]
    rows << cells.map { |x| x.to_s.include?(',') ? "\"#{x}\"" : x.to_s }.join(',')
  end
  rows.join("\n") + "\n"
end

# ---------------- 推送 ----------------

def push_token(cfg)
  t = ENV[cfg['token_env'].to_s].to_s.strip
  return t unless t.empty?
  return '' unless cfg['token_file'] && File.exist?(cfg['token_file'])
  File.read(cfg['token_file']).strip
end

# 地址里带订阅凭据的特征：查询串里的 target/token/auth/key，或 /sub/<长随机串> 这类面板路径
def secretish?(spec)
  url = spec['url'].to_s
  !!(url =~ /(?:\?|&)(?:target|token|auth|key|pass|password|secret|md5|uid|sid)=/i ||
     url =~ %r{/(?:sub|subscription|account|link)/[A-Za-z0-9_\-]{16,}})
end

# 标了 private: true 的上游（付费机场）里是你的专属凭据，绝不能进公开仓库。
# 这层校验放在抓节点之前：那时还没花掉十几分钟测速，失败也便宜。
def assert_repo_visibility(cfg, pushc)
  undecided = Array(cfg['upstreams']).select { |u| !u.key?('private') && secretish?(u) }
  unless undecided.empty?
    abort "上游 #{undecided.map { |u| u['name'] }.join('/')} 的地址看着带订阅凭据，却没标 private：拒绝盲推。" \
          '公开免费源就写 private: false，付费源就写 private: true'
  end
  priv = Array(cfg['upstreams']).select { |u| u['private'] }
  return if priv.empty?
  names = priv.map { |u| u['name'].to_s }.join('/')
  if pushc['method'].to_s == 'none'
    log "上游 #{names} 标了 private，push.method=none 只落本地文件，放行"
    return
  end
  raise 'push.repo 未配置，无法校验仓库可见性' if pushc['repo'].to_s.empty?
  r = gh_api(:get, "/repos/#{pushc['repo']}", nil, push_token(pushc))
  j = begin; JSON.parse(r.body.to_s); rescue StandardError; nil; end
  abort "查不到 push.repo=#{pushc['repo']}（HTTP #{r.code}）：拒绝在没确认可见性的情况下推送 private 上游" unless j
  abort "上游 #{names} 标了 private，但 #{pushc['repo']} 是公开仓库：已中止。改 push.repo 指向私有仓库，或 push.method: none 只留本地" if j['private'] != true
  log "已确认 #{pushc['repo']} 是私有仓库，private 上游 #{names} 可推"
end

def gh_api(method, path, body, tk)
  uri = URI("https://api.github.com#{path}")
  req = method == :get ? Net::HTTP::Get.new(uri) : Net::HTTP::Put.new(uri)
  req['Authorization'] = "Bearer #{tk}" unless tk.to_s.empty?
  req['Accept'] = 'application/vnd.github+json'
  req['User-Agent'] = 'autosub'
  if body
    req['Content-Type'] = 'application/json'
    req.body = JSON.generate(body)
  end
  tls_http(uri, 20, 120) { |h| h.request(req) }
end

# 更新已存在的文件必须带旧 blob sha。不能用 contents 接口去读：它会把整个文件的
# base64 一起返回（400 KB 订阅 = 550 KB 响应，实测 metadata+json 也一样带正文），
# 弱网下这种大响应最容易截断，截断就读不到 sha，于是每轮更新都失败。
# 改用 git trees 接口：整棵树 1 KB 左右，从里面按路径取 sha。
def read_sha(cfg, remote, tk, tries = 2)
  path = "/repos/#{cfg['repo']}/contents/#{remote}?ref=#{cfg['branch']}"
  last = nil
  tries.to_i.times do
    begin
      r = gh_api(:get, "/repos/#{cfg['repo']}/git/trees/#{cfg['branch']}?recursive=1", nil, tk)
      if r.code.to_i == 200
        j = JSON.parse(r.body.to_s)
        hit = Array(j['tree']).find { |e| e['path'].to_s == remote.to_s }
        return hit['sha'] if hit
        return nil unless j['truncated'] # 树里没有这个路径 = 新文件，PUT 不带 sha
      elsif r.code.to_i == 404
        return nil                       # 分支还不存在 = 首次推送
      else
        last = "HTTP #{r.code}"
      end
    rescue => e
      last = e.class.to_s
    end
    sleep(1)
  end
  # 树接口不可用（被截断/仓库过大被截断）时的兜底：还是读 contents，只是可能白跑一趟
  begin
    r = gh_api(:get, path, nil, tk)
    return JSON.parse(r.body.to_s)['sha'] if r.code.to_i == 200
  rescue => e
    last = e.class.to_s
  end
  log "  读取 #{remote} 现有 sha 未完成（#{last}）：按新建处理"
  nil
end

def push_api(cfg, work, files, note)
  tk = push_token(cfg)
  if tk.empty?
    log "  未推送：缺少 token（设置 #{cfg['token_env']} 或 push.token_file）"
    return nil
  end
  raise 'push.repo 未配置（owner/name）' if cfg['repo'].to_s.empty?
  shas = []
  ok = true
  Array(cfg['files']).each do |f|
    local = File.join(work, f['local'])
    remote = f['remote']
    unless File.exist?(local)
      log "  跳过 #{remote}：本地 #{f['local']} 不存在"
      next
    end
    content = File.binread(local)
    sha = read_sha(cfg, remote, tk)
    begin
      body = { 'message' => note, 'content' => Base64.strict_encode64(content), 'branch' => cfg['branch'] }
      body['sha'] = sha if sha
      r = gh_api(:put, "/repos/#{cfg['repo']}/contents/#{remote}", body, tk)
      if %w[409 422].include?(r.code.to_s) && !body.key?('sha')
        sha = read_sha(cfg, remote, tk, 3)
        if sha
          body['sha'] = sha
          r = gh_api(:put, "/repos/#{cfg['repo']}/contents/#{remote}", body, tk)
        end
      end
      if (200..299).cover?(r.code.to_i)
        j = JSON.parse(r.body.to_s)
        shas << j.dig('commit', 'sha')
        log "  已推送 #{remote}（#{content.bytesize} B，commit #{j.dig('commit', 'sha').to_s[0, 8]}）"
      else
        ok = false
        log "  推送 #{remote} 失败 HTTP #{r.code}: #{r.body.to_s[0, 160]}"
      end
    rescue => e
      ok = false
      log "  推送 #{remote} 异常 #{e.class}: #{e.message.to_s[0, 80]}"
    end
  end
  ok ? shas.compact.first : nil
end

def push_git(cfg, work, note)
  if cfg['repo_url'].to_s.empty?
    log '  push.repo_url 未配置，跳过 git 推送'
    return nil
  end
  dir = File.join(work, 'repo')
  system('git', 'clone', '--quiet', cfg['repo_url'], dir) unless File.directory?(File.join(dir, '.git'))
  return nil unless File.directory?(File.join(dir, '.git'))
  Array(cfg['files']).each do |f|
    src = File.join(work, f['local'])
    next unless File.exist?(src)
    dst = File.join(dir, f['remote'])
    FileUtils.mkdir_p(File.dirname(dst))
    FileUtils.cp(src, dst)
    system('git', '-C', dir, 'add', '--', f['remote'])
  end
  system('git', '-C', dir, 'commit', '-m', note)
  system('git', '-C', dir, 'push', 'origin', cfg['branch']) ? true : nil
end

# ---------------- 主流程 ----------------

# 测试可以 load 本文件只取函数，不执行主流程
return if defined?(AUTOSUB_LIB)

begin
  opts = { :stage => 'all', :dry => false }
  OptionParser.new do |o|
    o.banner = '用法: autosub.rb [-c sources.yaml] [--stage all|fetch|test|emit|push] [--dry-run]'
    o.on('-c FILE', '配置文件，默认 ./sources.yaml') { |v| opts[:cfg] = v }
    o.on('--stage NAME', 'all|fetch|test|emit|push') { |v| opts[:stage] = v }
    o.on('--dry-run', '生成文件但不推送') { opts[:dry] = true }
  end.parse!

  cfgfile = opts[:cfg] || File.join(Dir.pwd, 'sources.yaml')
  abort "找不到配置 #{cfgfile}" unless File.exist?(cfgfile)
  cfg = YAML.load_file(cfgfile)
  raise 'sources.yaml 顶层结构不对' unless cfg.is_a?(Hash)
  fcfg = FETCH_DEFAULTS.merge(Hash(cfg['fetch']))
  case fcfg['tls_max_version'].to_s
  when '', 'auto' then nil
  when '1.2' then $tls_max = OpenSSL::SSL::TLS1_2_VERSION
  else raise "fetch.tls_max_version 只接受 auto 或 1.2，收到 #{fcfg['tls_max_version'].inspect}"
  end
  hc = HC_DEFAULTS.merge(Hash(cfg['healthcheck']))
  outc = OUT_DEFAULTS.merge(Hash(cfg['output']))
  pushc = PUSH_DEFAULTS.merge(Hash(cfg['push']))
  # AUTOSUB_WORK_DIR 给 GitHub Actions 用：runner 是普通用户，/root 写不进去。
  work = ENV['AUTOSUB_WORK_DIR'] || cfg['work_dir'] || File.join(File.dirname(cfgfile), 'work')
  FileUtils.mkdir_p(work)
  assert_repo_visibility(cfg, pushc) if %w[all push].include?(opts[:stage]) && !opts[:dry]
  log "阶段=#{opts[:stage]} 工作目录=#{work}"

  # 1 抓取 + 解析
  raw = []
  src_stat = []
  Array(cfg['upstreams']).each do |spec|
    url, body = fetch_one(spec, work, fcfg)
    unless body
      src_stat << { 'name' => spec['name'], 'nodes' => 0, 'note' => '全部地址失败' }
      log "  #{spec['name']}: 拉取失败"
      next
    end
    list, skipped = parse_content(body, spec['name'])
    src_stat << { 'name' => spec['name'], 'nodes' => list.size, 'note' => "跳过不可识别 #{skipped}" }
    log "  #{spec['name']}: 解析 #{list.size} 个节点，跳过 #{skipped}"
    raw.concat(list)
  end
  abort '所有上游都没拿到节点' if raw.empty?
  log "上游合计 #{raw.size} 条"

  # 2 合并去重
  list = uniq_names!(dedupe(raw))
  log "去重后 #{list.size} 个"
  if Array(cfg['type_allowlist']).size > 0
    allow = Array(cfg['type_allowlist']).map { |t| t.to_s.downcase }
    n0 = list.size
    list = list.select { |p| allow.include?(p['type'].to_s.downcase) }
    log "协议白名单 #{allow.join('/')}：#{n0} -> #{list.size}"
  end
  # 上游数据里 REALITY 的 short-id 有 4 位、8 位的残值，还有 _spider-x 这类爬虫塞进来的
  # 野字段。mihomo 解析是全有全无的，一个非法值就整份配置起不来（实测 1052 个里中 106 枪）。
  # 置空而不是丢弃：不炸解析，也不少候选，能不能用交给测速裁决。
  fixed = sanitize!(list)
  log "修复非法 REALITY 字段 #{fixed} 个" if fixed > 0
  broken = drop_broken!(list)
  log "删掉会让内核整份拒绝的节点 #{broken.size} 个：#{broken.first(3).join('；')}" unless broken.empty?

  # 3 粘性排序：上次活着的优先，其次多源共现的优先
  alive_file = File.join(work, outc['alive_list'])
  prev = File.exist?(alive_file) ? File.readlines(alive_file).map(&:strip).reject(&:empty?) : []
  rank = {}
  prev.each_with_index { |n, i| rank[n] = i }
  list = list.sort_by { |p| [rank.key?(p['name']) ? 0 : 1, -(p['__hits'] || 1), p['name'].to_s] }
  # max_candidates 是「一轮测速最多测多少个」的耗时预算，只有真测速时才该拿它截断。
  # 不测速时拿它截等于先按名字砍掉一半候选，再在剩下的里面按共现挑 300 个——
  # 排序就在截断的前一行，截断排在排序之后才不破坏这个质量信号。
  # 测速关掉时唯一的输出预算是 output.max_nodes。
  max = hc['max_candidates'].to_i
  list = list.first(max) if max > 0 && hc['enabled'] != false
  log "候选 #{list.size} 个（上轮存活 #{prev.size}）"

  stats = {}
  alive = []
  tested = []
  if %w[all test push].include?(opts[:stage])
    if hc['enabled'] == false
      log 'healthcheck.enabled=false，跳过测速'
      list.each { |p| stats[p['name']] = { 'rounds' => 0, 'ok' => 0, 'median' => nil, 'errs' => 'skipped', 'alive' => false } }
    else
      stats, tested = healthcheck(list, hc)
      alive = tested.select { |p| stats[p['name']] && stats[p['name']]['alive'] }
      alive = alive.sort_by { |p| stats[p['name']]['median'].to_i }
      kinds = {}
      stats.each_value { |st| kinds[st['errs']] = (kinds[st['errs']] || 0) + 1 unless st['alive'] }
      log "存活 #{alive.size}/#{tested.size}（#{(alive.size * 100.0 / [tested.size, 1].max).round(1)}%）"
      log "失败分布: #{kinds.sort_by { |_, v| -v }.first(5).map { |k, v| "#{k}x#{v}" }.join('  ')}" unless kinds.empty?
      raw = $err_raw.uniq.reject { |s| s =~ /\AHTTP200/ }
      raw.first(8).each { |s| log "  失败样本 #{s}" } unless raw.empty?
    end
  end
  if opts[:stage] == 'fetch' || opts[:stage] == 'test'
    log "阶段 #{opts[:stage]} 完成"
    exit 0
  end

  # 4 产出
  # 发布集 = 本轮实测通过 ∪ 上一轮实测通过。另一半必须取「上轮实测」而不是「上轮发布」：
  # 跟上轮发布集取并集是单向棘轮，节点一旦进来就永远靠「上轮也发过」赖在名单里。
  # 取实测集则一个节点最多被带一次：本轮没过就不进本轮实测集，下轮没人替它说话，自动掉出去。
  # 只在真测过的轮次启用并集；单跑 stage=emit 或 healthcheck 关掉时本轮无实测，仍发全量。
  carry_nodes = []
  carry = {}
  if tested.any?
    pool = {}
    list.each { |p| pool[p['name']] ||= p }
    got = {}
    alive.each { |p| got[p['name']] = true }
    carry_nodes = prev.map { |n| pool[n] }.compact.reject { |p| got[p['name']] }
    carry_nodes.each { |p| carry[p['name']] = true }
  end
  emit_list = tested.any? ? alive + carry_nodes : list
  # 不测速时多源并集可能上千个，OpenClash 里没法用也拖慢选路。max_nodes 按命中次数（多源共现）
  # 降序截断——出现在越多独立订阅源里的节点越可能真实有效，这是不测速时唯一可用的质量信号。
  cap = outc['max_nodes'].to_i
  if tested.empty? && cap.positive? && emit_list.size > cap
    before = emit_list.size
    emit_list = emit_list.sort_by { |p| [-(p['__hits'] || 1), p['name'].to_s] }.first(cap)
    log "输出上限 #{cap}：按多源命中数从 #{before} 截到 #{emit_list.size}"
  end
  note = "生成 #{Time.now.strftime('%Y-%m-%d %H:%M:%S %z')}｜候选 #{list.size}｜存活 #{emit_list.size}"
  if tested.any? && !carry_nodes.empty?
    note += "（本轮 #{alive.size}+带过 #{carry_nodes.size}）"
    log "发布集 = 本轮 #{alive.size} + 上轮带过 #{carry_nodes.size} = #{emit_list.size}"
  end
  note += "｜ruby #{RUBY_VERSION}"
  yaml_text = build_yaml(emit_list, stats, note, carry, outc['rule_providers'] != false)
  min_alive = outc['min_alive'].to_i
  outpath = File.join(work, outc['path'])
  if emit_list.size < min_alive && File.exist?(outpath)
    log "存活 #{emit_list.size} < min_alive #{min_alive}：保留上一版，不覆盖 #{outpath}"
    exit 2
  end
  File.binwrite(outpath, yaml_text)
  File.binwrite(File.join(work, outc['stats']), build_csv(list, stats))
  if tested.any?
    # 全灭也照写：空名单就是下一轮没有可带的人，这是并集机制里唯一的衰减，不能省。
    File.binwrite(alive_file, alive.map { |p| p['name'] }.join("\n") + (alive.empty? ? '' : "\n"))
  else
    log '本轮未实测（跳过测速或 stage=emit），previous_alive.txt 保持不动'
  end
  File.binwrite(File.join(work, outc['manifest']), JSON.pretty_generate(
    'generated_at' => Time.now.iso8601, 'sources' => src_stat,
    'candidates' => list.size, 'alive' => emit_list.size,
    'alive_this_run' => alive.size, 'carried' => carry_nodes.size,
    'alive_ratio' => (emit_list.size * 100.0 / [list.size, 1].max).round(2),
    'best_median_ms' => alive.empty? ? nil : stats[alive.first['name']]['median'],
    'types' => emit_list.group_by { |p| p['type'].to_s }.map { |k, v| { 'type' => k, 'n' => v.size } }
  ))
  log "已写出 #{outpath}（#{yaml_text.bytesize} B）"

  if opts[:dry] || opts[:stage] == 'emit'
    log '未推送（--dry-run 或 stage=emit）'
    exit 0
  end

  # 5 推送
  note2 = "autosub #{Time.now.strftime('%Y-%m-%d %H:%M')} 候选#{list.size} 存活#{emit_list.size}"
  sha = pushc['method'].to_s == 'git' ? push_git(pushc, work, note2) : push_api(pushc, work, nil, note2)
  if sha
    log '订阅地址（用 commit SHA 固定，避开 jsdelivr 按 size 生成的弱 ETag 卡 7 天缓存）：'
    log "  https://raw.githubusercontent.com/#{pushc['repo']}/#{sha}/#{Array(pushc['files']).first['remote']}"
    log "  https://fastly.jsdelivr.net/gh/#{pushc['repo']}@#{sha}/#{Array(pushc['files']).first['remote']}"
  elsif pushc['method'].to_s == 'none'
    log 'push.method=none，仅本地文件'
  else
    log '推送未完成，产出文件已在工作目录'
  end
rescue SystemExit
  raise
rescue Interrupt
  abort '已中断'
rescue => e
  log "失败：#{e.class}: #{e.message}"
  log "回溯：#{e.backtrace.to_a.first(2).join(" <- ")}" if ENV["AUTOSUB_DEBUG"]
  exit 1
end
