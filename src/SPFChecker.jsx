import React, { useState } from 'react';
import { Search, CheckCircle, AlertTriangle, ChevronRight, ChevronDown, Minus } from 'lucide-react';

// IPv4 CIDR에서 주소 수 계산
const calculateIPv4Count = (cidr) => {
  const [, bits] = cidr.split('/');
  const prefixLength = bits ? parseInt(bits) : 32;
  return Math.pow(2, 32 - prefixLength);
};

// SPF 레코드를 재귀적으로 조회하는 함수
const resolveSPFRecord = async (domain, depth = 0, visited = new Set()) => {
  if (depth > 10 || visited.has(domain)) {
    return { record: null, error: 'max-depth', isVoid: false };
  }

  visited.add(domain);

  try {
    const response = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`
    );

    if (!response.ok) {
      return { record: null, error: 'network', isVoid: false };
    }

    const data = await response.json();

    // NXDOMAIN (RCODE 3) 또는 SERVFAIL (RCODE 2)
    if (data.Status === 3) {
      return { record: null, error: 'nxdomain', isVoid: true };
    }

    if (data.Status === 2) {
      return { record: null, error: 'servfail', isVoid: false };
    }

    // 응답이 없거나 Answer가 비어있음 (void lookup)
    if (data.Status !== 0 || !data.Answer || data.Answer.length === 0) {
      return { record: null, error: 'no-answer', isVoid: true };
    }

    // SPF 레코드 찾기 - 모든 SPF 레코드를 찾아서 다중 레코드 검증
    const spfRecords = data.Answer.filter(answer =>
      answer.data && (answer.data.includes('v=spf1') || answer.data.includes('"v=spf1'))
    );

    if (spfRecords.length === 0) {
      return { record: null, error: 'no-spf', isVoid: false };
    }

    // RFC 7208: 다중 SPF 레코드는 PermError
    if (spfRecords.length > 1) {
      return {
        record: null,
        error: 'multiple-spf',
        isVoid: false,
        records: spfRecords.map(r => r.data.replace(/"/g, '').trim())
      };
    }

    // 따옴표 제거
    const recordText = spfRecords[0].data.replace(/"/g, '').trim();

    return { record: recordText, error: null, isVoid: false };
  } catch (error) {
    console.error(`Error resolving ${domain}:`, error);
    return { record: null, error: 'exception', isVoid: false };
  }
};

// SPF 레코드 파싱 및 트리 구조 생성
const parseSPFTree = async (domain, depth = 0, visited = new Set(), context = { voidLookups: 0, warnings: [], errors: [] }) => {
  if (depth > 10 || visited.has(domain)) {
    context.errors.push(`최대 깊이 초과 또는 순환 참조 감지: ${domain}`);
    return null;
  }

  const result = await resolveSPFRecord(domain, depth, new Set(visited));

  // Void lookup 추적 (RFC 7208: 최대 2회 권장)
  if (result.isVoid) {
    context.voidLookups += 1;
    if (context.voidLookups > 2) {
      context.errors.push(`Void lookup 제한 초과 (${context.voidLookups}/2): ${domain}`);
    }
  }

  // 다중 SPF 레코드 에러
  if (result.error === 'multiple-spf') {
    context.errors.push(`PermError: 도메인 ${domain}에 여러 개의 SPF 레코드가 존재합니다. RFC 7208에 따라 하나의 레코드만 허용됩니다.`);
    return null;
  }

  if (!result.record) {
    if (result.error === 'nxdomain') {
      context.warnings.push(`도메인 ${domain}이 존재하지 않습니다 (NXDOMAIN)`);
    } else if (result.error === 'no-spf') {
      context.warnings.push(`도메인 ${domain}에 SPF 레코드가 없습니다`);
    }
    return null;
  }

  const record = result.record;

  // RFC 7208: v=spf1이 첫 번째여야 함
  if (!record.startsWith('v=spf1')) {
    context.errors.push(`잘못된 SPF 레코드 형식: v=spf1로 시작해야 합니다 (도메인: ${domain})`);
  }

  // 레코드 길이 검증 (RFC 7208: 512 옥텟 이하 권장)
  const recordLength = new TextEncoder().encode(record).length;
  if (recordLength > 512) {
    context.errors.push(`레코드 길이 초과: ${recordLength} 옥텟 (512 옥텟 이하 권장, 도메인: ${domain})`);
  } else if (recordLength > 450) {
    context.warnings.push(`레코드 길이 주의: ${recordLength} 옥텟 (450 옥텟 이하 권장, UDP 호환성, 도메인: ${domain})`);
  }

  visited.add(domain);

  const mechanisms = record.split(/\s+/).filter(m => m.trim());
  const children = [];
  let dnsLookups = 0;
  const netblocks = [];
  let allFound = false;

  for (let i = 0; i < mechanisms.length; i++) {
    const trimmed = mechanisms[i].trim();

    // all 이후 메커니즘은 무시됨 (RFC 7208)
    if (allFound) {
      context.warnings.push(`'all' 메커니즘 이후의 메커니즘은 무시됩니다: ${trimmed} (도메인: ${domain})`);
      continue;
    }

    // qualifier 추출
    const getQualifier = (mech) => {
      const first = mech.charAt(0);
      if (['+', '-', '~', '?'].includes(first)) return first;
      return '+'; // 기본값
    };

    // include 처리
    if (trimmed.match(/^(\+|-|~|\?)?include:/)) {
      const qualifier = getQualifier(trimmed);
      const includeDomain = trimmed.replace(/^(\+|-|~|\?)?include:/, '');
      dnsLookups += 1;

      const child = await parseSPFTree(includeDomain, depth + 1, new Set(visited), context);
      if (child) {
        children.push({
          type: 'include',
          mechanism: trimmed.startsWith('+') || ['-', '~', '?'].includes(trimmed.charAt(0)) ? trimmed : `+${trimmed}`,
          domain: includeDomain,
          record: child.record,
          children: child.children,
          dnsLookups: child.dnsLookups + 1,
          netblocks: child.netblocks,
          qualifier
        });
        dnsLookups += child.dnsLookups;
        netblocks.push(...child.netblocks);
      }
    }
    // redirect 처리
    else if (trimmed.startsWith('redirect=')) {
      if (allFound) {
        context.warnings.push(`redirect는 'all' 메커니즘이 있을 때 무시됩니다 (도메인: ${domain})`);
        continue;
      }
      const redirectDomain = trimmed.substring(9);
      dnsLookups += 1;

      const child = await parseSPFTree(redirectDomain, depth + 1, new Set(visited), context);
      if (child) {
        children.push({
          type: 'redirect',
          mechanism: trimmed,
          domain: redirectDomain,
          record: child.record,
          children: child.children,
          dnsLookups: child.dnsLookups + 1,
          netblocks: child.netblocks
        });
        dnsLookups += child.dnsLookups;
        netblocks.push(...child.netblocks);
      }
    }
    // ip4 처리
    else if (trimmed.match(/^(\+|-|~|\?)?ip4:/)) {
      const ip = trimmed.replace(/^(\+|-|~|\?)?ip4:/, '');
      const cidr = ip.includes('/') ? ip : `${ip}/32`;
      netblocks.push(cidr);
      children.push({
        type: 'ip4',
        mechanism: trimmed.startsWith('+') || ['-', '~', '?'].includes(trimmed.charAt(0)) ? trimmed : `+${trimmed}`,
        value: cidr,
        count: calculateIPv4Count(cidr)
      });
    }
    // ip6 처리
    else if (trimmed.match(/^(\+|-|~|\?)?ip6:/)) {
      const ip = trimmed.replace(/^(\+|-|~|\?)?ip6:/, '');
      children.push({
        type: 'ip6',
        mechanism: trimmed.startsWith('+') || ['-', '~', '?'].includes(trimmed.charAt(0)) ? trimmed : `+${trimmed}`,
        value: ip
      });
    }
    // ptr 처리 (사용 권장하지 않음)
    else if (trimmed.match(/^(\+|-|~|\?)?ptr(:|$)/i)) {
      dnsLookups += 1;
      context.warnings.push(`PTR 메커니즘은 성능과 신뢰성 문제로 인해 RFC 7208에서 사용을 권장하지 않습니다 (도메인: ${domain})`);
      children.push({
        type: 'ptr',
        mechanism: trimmed,
        dnsLookups: 1
      });
    }
    // a 처리 (DNS 조회 필요)
    else if (trimmed.match(/^(\+|-|~|\?)?a(:|\/|$)/i)) {
      dnsLookups += 1;
      children.push({
        type: 'a',
        mechanism: trimmed,
        dnsLookups: 1
      });
    }
    // mx 처리 (DNS 조회 필요)
    else if (trimmed.match(/^(\+|-|~|\?)?mx(:|\/|$)/i)) {
      dnsLookups += 1;
      context.warnings.push(`MX 메커니즘은 추가 DNS 조회가 필요합니다. 각 MX 레코드는 최대 10개의 A/AAAA 레코드를 조회할 수 있습니다 (도메인: ${domain})`);
      children.push({
        type: 'mx',
        mechanism: trimmed,
        dnsLookups: 1
      });
    }
    // exists 처리 (DNS 조회 필요)
    else if (trimmed.match(/^(\+|-|~|\?)?exists:/i)) {
      dnsLookups += 1;
      children.push({
        type: 'exists',
        mechanism: trimmed,
        dnsLookups: 1
      });
    }
    // all 처리
    else if (trimmed.match(/^(\+|-|~|\?)?all$/)) {
      allFound = true;
      const qualifier = trimmed.charAt(0);
      children.push({
        type: 'all',
        mechanism: trimmed,
        qualifier: qualifier === '~' ? 'softfail' :
                   qualifier === '-' ? 'fail' :
                   qualifier === '?' ? 'neutral' : 'pass',
        position: i
      });
    }
    // 알 수 없는 메커니즘
    else if (!trimmed.startsWith('v=spf1')) {
      context.warnings.push(`알 수 없는 메커니즘 또는 수정자: ${trimmed} (도메인: ${domain})`);
    }
  }

  return {
    domain,
    record,
    children,
    dnsLookups,
    netblocks,
    warnings: context.warnings,
    errors: context.errors,
    voidLookups: context.voidLookups
  };
};

// SPF 트리 노드 컴포넌트
const SPFTreeNode = ({ node, domain, depth = 0, onToggle, expanded }) => {
  const isExpanded = expanded[`${domain}-${depth}`];
  const hasChildren = node.children && node.children.length > 0;
  const indent = depth * 36;

  const getDNSLookupTag = (dnsLookups) => {
    if (dnsLookups === undefined || dnsLookups === 0) return null;
    return (
      <span className="inline-flex items-center justify-center w-6 h-6 text-xs font-semibold bg-blue-100 text-blue-800 rounded mr-2">
        {dnsLookups}
      </span>
    );
  };

  const getQualifierText = (qualifier) => {
    switch (qualifier) {
      case 'softfail': return '~all (Soft Fail)';
      case 'fail': return '-all (Fail)';
      case 'neutral': return '?all (Neutral)';
      case 'pass': return '+all (Pass)';
      default: return qualifier;
    }
  };

  if (node.type === 'ip4' || node.type === 'ip6') {
    return (
      <div style={{ marginTop: '5px', paddingLeft: `${indent}px` }}>
        <div className="bg-white border border-gray-200 rounded">
          <code className="block p-3 text-sm font-mono text-gray-800">
            {node.mechanism}
          </code>
        </div>
      </div>
    );
  }

  if (node.type === 'all') {
    return (
      <div style={{ marginTop: '5px', paddingLeft: `${indent}px` }}>
        <div className="bg-white border border-gray-200 rounded">
          <code className="block p-3 text-sm font-mono text-gray-800">
            {getQualifierText(node.qualifier)}
          </code>
        </div>
      </div>
    );
  }

  if (node.type === 'a' || node.type === 'mx' || node.type === 'exists' || node.type === 'ptr') {
    return (
      <div style={{ marginTop: '5px', paddingLeft: `${indent}px` }}>
        <div className={`bg-white border rounded ${
          node.type === 'ptr' ? 'border-yellow-300 bg-yellow-50' : 'border-gray-200'
        }`}>
          <div className="flex items-center p-3 border-b border-gray-200 bg-gray-50">
            <Minus size={20} className="mr-2 text-gray-400" />
            {getDNSLookupTag(node.dnsLookups)}
            <span className="text-sm font-semibold text-gray-800">{node.mechanism}</span>
            {node.type === 'ptr' && (
              <span className="ml-2 text-xs bg-yellow-200 text-yellow-800 px-2 py-1 rounded">
                권장하지 않음
              </span>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ marginTop: '5px', paddingLeft: `${indent}px` }}>
      <div className="bg-white border border-gray-200 rounded">
        {hasChildren && (
          <div
            className="flex items-center p-3 border-b border-gray-200 bg-gray-50 cursor-pointer hover:bg-gray-100"
            onClick={() => onToggle(`${domain}-${depth}`)}
          >
            {isExpanded ? (
              <ChevronDown size={20} className="mr-2 text-gray-600" />
            ) : (
              <ChevronRight size={20} className="mr-2 text-gray-600" />
            )}
            {getDNSLookupTag(node.dnsLookups)}
            <span className="text-sm font-semibold text-gray-800">{node.domain}</span>
          </div>
        )}

        <code className="block p-3 text-sm font-mono text-gray-800 bg-white">
          {node.record}
        </code>

        {isExpanded && hasChildren && (
          <div className="bg-gray-50">
            {node.children.map((child, idx) => (
              <SPFTreeNode
                key={idx}
                node={child}
                domain={child.domain || `${domain}-child-${idx}`}
                depth={depth + 1}
                onToggle={onToggle}
                expanded={expanded}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default function SPFChecker() {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState({});

  const checkSPF = async () => {
    if (!domain.trim()) {
      setError('도메인을 입력해주세요.');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);
    setExpanded({});

    try {
      const spfTree = await parseSPFTree(domain.trim());

      if (!spfTree) {
        setError('SPF 레코드를 찾을 수 없습니다.');
        setLoading(false);
        return;
      }

      // 중복 네트블록 찾기
      const netblockCount = {};
      spfTree.netblocks.forEach(nb => {
        netblockCount[nb] = (netblockCount[nb] || 0) + 1;
      });

      const duplicates = Object.entries(netblockCount)
        .filter(([, count]) => count > 1)
        .map(([netblock, count]) => ({ netblock, count }));

      // 총 IPv4 주소 수 계산
      const uniqueNetblocks = [...new Set(spfTree.netblocks)];
      const totalIPv4Count = uniqueNetblocks.reduce((sum, nb) => {
        return sum + calculateIPv4Count(nb);
      }, 0);

      setResult({
        tree: spfTree,
        dnsLookups: spfTree.dnsLookups,
        netblockCount: uniqueNetblocks.length,
        ipv4Count: totalIPv4Count,
        duplicates,
        warnings: spfTree.warnings || [],
        errors: spfTree.errors || [],
        voidLookups: spfTree.voidLookups || 0
      });

      // 자동으로 루트 노드 확장
      setExpanded({ [`${domain}-0`]: true });
    } catch (err) {
      setError(err.message || '오류가 발생했습니다.');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      checkSPF();
    }
  };

  const toggleNode = (key) => {
    setExpanded(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  const expandAll = () => {
    const allKeys = {};
    const expand = (node, domain, depth) => {
      allKeys[`${domain}-${depth}`] = true;
      if (node.children) {
        node.children.forEach((child, idx) => {
          if (child.domain) {
            expand(child, child.domain, depth + 1);
          }
        });
      }
    };
    if (result) {
      expand(result.tree, result.tree.domain, 0);
    }
    setExpanded(allKeys);
  };

  const collapseAll = () => {
    setExpanded({});
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-50 to-teal-100 p-4">
      <div className="max-w-6xl mx-auto py-8">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-800 mb-2">
            SPF 레코드 검색기
          </h1>
          <p className="text-gray-600">
            도메인의 SPF 레코드를 확인하고 분석하세요
          </p>
        </div>

        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <div className="flex gap-3">
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="example.com"
              className="flex-1 px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent outline-none"
            />
            <button
              onClick={checkSPF}
              disabled={loading}
              className="px-6 py-3 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center gap-2 font-medium transition-colors"
            >
              <Search size={20} />
              {loading ? '조회 중...' : '검색'}
            </button>
          </div>
        </div>

        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
            <div className="flex items-start gap-3">
              <AlertTriangle className="text-red-600 flex-shrink-0" size={24} />
              <div>
                <h3 className="font-semibold text-red-800 mb-1">오류</h3>
                <p className="text-red-700">{error}</p>
              </div>
            </div>
          </div>
        )}

        {result && (
          <div className="space-y-6">
            {/* 성공/경고/에러 메시지 */}
            {result.errors.length > 0 ? (
              <div className="bg-red-50 border border-red-200 rounded-lg p-6">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="text-red-600 flex-shrink-0" size={24} />
                  <div className="flex-1">
                    <h3 className="font-semibold text-red-800 text-lg mb-1">
                      SPF 레코드에 심각한 문제가 있습니다!
                    </h3>
                    <p className="text-red-700 text-sm mb-3">
                      RFC 7208 표준을 위반하는 에러가 발견되었습니다.
                    </p>
                    <ul className="space-y-1">
                      {result.errors.map((err, idx) => (
                        <li key={idx} className="text-sm text-red-700 flex items-start gap-2">
                          <span className="mt-1">•</span>
                          <span>{err}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            ) : result.dnsLookups > 10 ? (
              <div className="bg-red-50 border border-red-200 rounded-lg p-6">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="text-red-600 flex-shrink-0" size={24} />
                  <div>
                    <h3 className="font-semibold text-red-800 text-lg mb-1">
                      SPF 레코드에 문제가 있습니다!
                    </h3>
                    <p className="text-red-700 text-sm">
                      DNS 조회 수가 10을 초과했습니다 ({result.dnsLookups}/10). SPF 레코드를 최적화해야 합니다.
                    </p>
                  </div>
                </div>
              </div>
            ) : (
              <div className="bg-green-50 border border-green-200 rounded-lg p-6">
                <div className="flex items-start gap-3">
                  <CheckCircle className="text-green-600 flex-shrink-0" size={24} />
                  <div>
                    <h3 className="font-semibold text-green-800 text-lg mb-1">
                      SPF 레코드가 유효합니다!
                    </h3>
                    <p className="text-green-700 text-sm">
                      SPF 레코드가 RFC 7208 표준을 준수합니다.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* 경고 메시지 */}
            {result.warnings.length > 0 && (
              <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-6">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="text-yellow-600 flex-shrink-0" size={24} />
                  <div className="flex-1">
                    <h3 className="font-semibold text-yellow-800 text-lg mb-2">
                      권장사항 및 경고
                    </h3>
                    <ul className="space-y-1">
                      {result.warnings.map((warning, idx) => (
                        <li key={idx} className="text-sm text-yellow-700 flex items-start gap-2">
                          <span className="mt-1">•</span>
                          <span>{warning}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            )}

            {/* 통계 */}
            <div className="bg-white rounded-lg shadow-lg p-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div>
                  <div className="flex items-start mb-3">
                    <div className={`text-3xl font-bold mr-3 ${
                      result.dnsLookups <= 10 ? 'text-green-600' : 'text-red-600'
                    }`}>
                      {result.dnsLookups}/10
                    </div>
                    <div>
                      <div className="font-semibold text-gray-800">
                        DNS 조회 수
                      </div>
                    </div>
                  </div>
                  <p className="text-sm text-gray-600">
                    {result.dnsLookups > 8
                      ? '조회 수가 높습니다. DMARC 데이터를 기반으로 검토 및 조정이 필요합니다.'
                      : 'SPF 레코드의 DNS 조회 수가 적절합니다.'}
                  </p>
                </div>

                <div>
                  <div className="flex items-start mb-3">
                    <div className="text-3xl font-bold text-blue-600 mr-3">
                      {result.netblockCount}
                    </div>
                    <div>
                      <div className="font-semibold text-gray-800">
                        승인된 네트블록
                      </div>
                      <div className="text-sm text-gray-500">
                        {result.ipv4Count.toLocaleString()} IPv4 주소
                      </div>
                    </div>
                  </div>
                  <p className="text-sm text-gray-600">
                    정기적으로 SPF 레코드를 검토하여 필요한 네트블록만 포함되어 있는지 확인하는 것이 중요합니다.
                  </p>
                </div>

                <div>
                  <div className="flex items-start mb-3">
                    <div className={`text-3xl font-bold mr-3 ${
                      result.voidLookups > 2 ? 'text-red-600' :
                      result.voidLookups > 0 ? 'text-yellow-600' : 'text-green-600'
                    }`}>
                      {result.voidLookups}/2
                    </div>
                    <div>
                      <div className="font-semibold text-gray-800">
                        Void Lookups
                      </div>
                      <div className="text-sm text-gray-500">
                        빈 응답 조회
                      </div>
                    </div>
                  </div>
                  <p className="text-sm text-gray-600">
                    {result.voidLookups > 2
                      ? 'RFC 7208: Void lookup이 2회를 초과했습니다.'
                      : 'DNS 응답이 없거나 NXDOMAIN인 조회 횟수입니다.'}
                  </p>
                </div>
              </div>
            </div>

            {/* SPF 레코드 트리 */}
            <div className="bg-white rounded-lg shadow-lg p-6">
              <div className="mb-4">
                <p className="text-sm text-gray-600 mb-2">노드를 클릭하여 확장하세요.</p>
                <div className="flex gap-2">
                  <button
                    onClick={expandAll}
                    className="px-4 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700 transition-colors"
                  >
                    모두 확장
                  </button>
                  <button
                    onClick={collapseAll}
                    className="px-4 py-2 bg-gray-600 text-white text-sm rounded hover:bg-gray-700 transition-colors"
                  >
                    모두 접기
                  </button>
                </div>
              </div>

              <h3 className="text-xl font-bold text-gray-800 mb-4">SPF 레코드</h3>

              <div className="bg-white border border-gray-200 rounded">
                <div
                  className="flex items-center p-3 border-b border-gray-200 bg-gray-50 cursor-pointer hover:bg-gray-100"
                  onClick={() => toggleNode(`${result.tree.domain}-0`)}
                >
                  {expanded[`${result.tree.domain}-0`] ? (
                    <ChevronDown size={20} className="mr-2 text-gray-600" />
                  ) : (
                    <ChevronRight size={20} className="mr-2 text-gray-600" />
                  )}
                  <span className="inline-flex items-center justify-center w-6 h-6 text-xs font-semibold bg-blue-100 text-blue-800 rounded mr-2">
                    {result.dnsLookups}
                  </span>
                  <span className="text-sm font-semibold text-gray-800">{result.tree.domain}</span>
                </div>

                <code className="block p-3 text-sm font-mono text-gray-800 bg-white border-b border-gray-200">
                  {result.tree.record}
                </code>

                {expanded[`${result.tree.domain}-0`] && result.tree.children && (
                  <div className="bg-gray-50 p-2">
                    {result.tree.children.map((child, idx) => (
                      <SPFTreeNode
                        key={idx}
                        node={child}
                        domain={child.domain || `${result.tree.domain}-child-${idx}`}
                        depth={1}
                        onToggle={toggleNode}
                        expanded={expanded}
                      />
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* 중복 네트블록 */}
            {result.duplicates.length > 0 && (
              <div className="bg-white rounded-lg shadow-lg p-6">
                <h3 className="text-lg font-bold text-gray-800 mb-3">중복 네트블록</h3>
                <p className="text-sm text-gray-600 mb-4">
                  다음 네트블록이 두 번 이상 승인되었습니다. 중복은 일반적으로 비효율적인 레코드나
                  중복된 "include" 메커니즘을 나타내며 제거해야 합니다.
                </p>

                <div className="overflow-x-auto">
                  <table className="min-w-full border border-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-4 py-3 text-left text-sm font-semibold text-gray-700 border-b">
                          네트블록
                        </th>
                        <th className="px-4 py-3 text-left text-sm font-semibold text-gray-700 border-b">
                          발생 횟수
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white">
                      {result.duplicates.map(({ netblock, count }, idx) => (
                        <tr key={idx} className="border-b border-gray-200 hover:bg-gray-50">
                          <td className="px-4 py-3 text-sm text-gray-800 font-mono">
                            {netblock}
                          </td>
                          <td className="px-4 py-3 text-sm text-gray-800">
                            {count}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* 정보 박스 */}
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
              <h3 className="font-semibold text-blue-800 mb-2">레코드 최적화</h3>
              <p className="text-sm text-blue-700 mb-2">
                SPF의 10 DNS 조회 제한을 해결하는 방법에 대한 도움말을 확인하세요.
              </p>
              <p className="text-sm text-blue-700">
                SPF Flattening은 권장하지 않습니다. SPF 레코드는 정기적으로 검토하고
                필요하지 않은 include를 제거하는 것이 가장 좋습니다.
              </p>
            </div>
          </div>
        )}

        {!result && !error && (
          <div className="bg-white rounded-lg shadow-lg p-6">
            <h3 className="font-semibold text-gray-800 mb-3">테스트해볼 도메인 예시:</h3>
            <div className="flex flex-wrap gap-2">
              {['nhn.com', 'google.com', 'microsoft.com', 'github.com'].map(d => (
                <button
                  key={d}
                  onClick={() => setDomain(d)}
                  className="px-4 py-2 bg-gray-100 hover:bg-gray-200 rounded-lg text-gray-700 text-sm transition-colors"
                >
                  {d}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
