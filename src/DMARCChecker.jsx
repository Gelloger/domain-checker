import React, { useState } from 'react';
import { Search, CheckCircle, XCircle, AlertTriangle, Info } from 'lucide-react';

// RFC 7489에 정의된 모든 DMARC 태그 정의
const DMARC_TAGS = {
    v: {
      name: 'Version',
      description: 'DMARC 프로토콜 버전 (항상 DMARC1이어야 함)',
      required: true,
      default: null
    },
    p: {
      name: 'Policy',
      description: '도메인에 대한 정책 (none, quarantine, reject)',
      required: true,
      default: null
    },
    sp: {
      name: 'Subdomain Policy',
      description: '하위 도메인에 적용할 정책 (none, quarantine, reject)',
      required: false,
      default: 'p 태그 값과 동일'
    },
    rua: {
      name: 'Aggregate Report URI',
      description: '집계 보고서를 받을 URI (mailto: 또는 https:)',
      required: false,
      default: null
    },
    ruf: {
      name: 'Forensic Report URI',
      description: '실패 보고서를 받을 URI (mailto: 또는 https:)',
      required: false,
      default: null
    },
    pct: {
      name: 'Percentage',
      description: 'DMARC 정책을 적용할 메시지 비율 (0-100)',
      required: false,
      default: '100'
    },
    adkim: {
      name: 'DKIM Alignment',
      description: 'DKIM 정렬 모드 (r=relaxed, s=strict)',
      required: false,
      default: 'r'
    },
    aspf: {
      name: 'SPF Alignment',
      description: 'SPF 정렬 모드 (r=relaxed, s=strict)',
      required: false,
      default: 'r'
    },
    fo: {
      name: 'Failure Reporting Options',
      description: '실패 보고 옵션 (0, 1, d, s 또는 조합)',
      required: false,
      default: '0'
    },
    rf: {
      name: 'Report Format',
      description: '실패 보고서 형식',
      required: false,
      default: 'afrf'
    },
    ri: {
      name: 'Report Interval',
      description: '집계 보고서 간격 (초 단위)',
      required: false,
      default: '86400'
    }
};

const parseDMARCRecord = (record) => {
    const tags = {};
    const pairs = record.split(';').map(p => p.trim()).filter(p => p);

    pairs.forEach((pair, index) => {
      const [key, value] = pair.split('=').map(s => s.trim());
      if (key && value) {
        tags[key] = { value, position: index };
      }
    });

    return tags;
};

const validateDMARCRecord = (tags, record) => {
    const issues = [];
    const recommendations = [];

    // RFC 7489: v 태그가 첫 번째에 와야 함
    const firstTag = record.split(';')[0].trim().split('=')[0].trim();
    if (firstTag !== 'v') {
      issues.push('RFC 7489 위반: v 태그가 DMARC 레코드의 첫 번째 태그여야 합니다.');
    }

    // v 태그 검증 (필수)
    if (!tags.v || tags.v.value !== 'DMARC1') {
      issues.push('v 태그가 없거나 올바르지 않습니다. v=DMARC1이어야 합니다.');
    }

    // p 태그 검증 (필수)
    if (!tags.p) {
      issues.push('p 태그(정책)가 없습니다. none, quarantine, reject 중 하나여야 합니다.');
    } else if (!['none', 'quarantine', 'reject'].includes(tags.p.value)) {
      issues.push(`p 태그 값이 올바르지 않습니다: ${tags.p.value}`);
    } else if (tags.p.value === 'none') {
      recommendations.push('p=none은 모니터링 모드입니다. 보안 강화를 위해 quarantine 또는 reject로 업그레이드를 고려하세요.');
    }

    // sp 태그 검증
    if (tags.sp && !['none', 'quarantine', 'reject'].includes(tags.sp.value)) {
      issues.push(`sp 태그 값이 올바르지 않습니다: ${tags.sp.value}`);
    }

    // rua 태그 검증 (URI 형식)
    if (tags.rua) {
      const uris = tags.rua.value.split(',');
      uris.forEach(uri => {
        uri = uri.trim();
        if (!uri.startsWith('mailto:') && !uri.startsWith('https://')) {
          issues.push(`rua URI가 올바르지 않습니다: ${uri}. mailto: 또는 https:로 시작해야 합니다.`);
        }
      });
    } else {
      recommendations.push('rua 태그를 추가하여 집계 보고서를 받을 URI를 지정하세요.');
    }

    // ruf 태그 검증 (URI 형식)
    if (tags.ruf) {
      const uris = tags.ruf.value.split(',');
      uris.forEach(uri => {
        uri = uri.trim();
        if (!uri.startsWith('mailto:') && !uri.startsWith('https://')) {
          issues.push(`ruf URI가 올바르지 않습니다: ${uri}. mailto: 또는 https:로 시작해야 합니다.`);
        }
      });
    } else {
      recommendations.push('ruf 태그를 추가하여 실패 보고서를 받을 URI를 지정하세요.');
    }

    // pct 태그 검증
    if (tags.pct) {
      const pct = parseInt(tags.pct.value);
      if (isNaN(pct) || pct < 0 || pct > 100) {
        issues.push('pct 태그는 0-100 사이의 정수여야 합니다.');
      } else if (pct < 100) {
        recommendations.push(`pct=${pct}로 설정되어 있어 ${pct}%의 메시지에만 정책이 적용됩니다. 100%로 설정하는 것을 고려하세요.`);
      }
    }

    // adkim 태그 검증
    if (tags.adkim && !['r', 's'].includes(tags.adkim.value)) {
      issues.push('adkim 태그는 r(relaxed) 또는 s(strict)여야 합니다.');
    }

    // aspf 태그 검증
    if (tags.aspf && !['r', 's'].includes(tags.aspf.value)) {
      issues.push('aspf 태그는 r(relaxed) 또는 s(strict)여야 합니다.');
    }

    // fo 태그 검증
    if (tags.fo) {
      const validFoValues = ['0', '1', 'd', 's'];
      const foValues = tags.fo.value.split(':');
      const invalidValues = foValues.filter(v => !validFoValues.includes(v));
      if (invalidValues.length > 0) {
        issues.push(`fo 태그에 유효하지 않은 값이 포함되어 있습니다: ${invalidValues.join(', ')}. 유효한 값: 0, 1, d, s`);
      }
      // RFC 7489: fo 태그는 ruf 태그와 함께 사용되어야 함
      if (!tags.ruf) {
        recommendations.push('fo 태그가 설정되어 있지만 ruf 태그가 없습니다. ruf 태그를 추가하여 실패 보고서를 받을 수 있도록 하세요.');
      }
    }

    // rf 태그 검증
    if (tags.rf) {
      const validRfValues = ['afrf', 'iodef'];
      if (!validRfValues.includes(tags.rf.value)) {
        issues.push(`rf 태그 값이 올바르지 않습니다: ${tags.rf.value}. 유효한 값: afrf, iodef`);
      }
    }

    // ri 태그 검증
    if (tags.ri) {
      const ri = parseInt(tags.ri.value);
      if (isNaN(ri) || ri < 0) {
        issues.push('ri 태그는 0 이상의 정수여야 합니다 (초 단위).');
      }
    }

    return { issues, recommendations };
};

const getPolicyColor = (policy) => {
    switch(policy) {
      case 'reject': return 'text-green-600';
      case 'quarantine': return 'text-yellow-600';
      case 'none': return 'text-orange-600';
      default: return 'text-gray-600';
    }
};

const getPolicyDescription = (policy) => {
    switch(policy) {
      case 'reject': return '실패한 이메일 거부 (최고 보안)';
      case 'quarantine': return '실패한 이메일 격리 (중간 보안)';
      case 'none': return '모니터링만 실행 (낮은 보안)';
      default: return '알 수 없음';
    }
};

export default function DMARCChecker() {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const checkDMARC = async () => {
    if (!domain.trim()) {
      setError('도메인을 입력해주세요.');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      // Google DNS API를 사용하여 DMARC 레코드 조회
      const dmarcDomain = `_dmarc.${domain.trim()}`;
      const response = await fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(dmarcDomain)}&type=TXT`
      );

      if (!response.ok) {
        throw new Error('DNS 조회에 실패했습니다.');
      }

      const data = await response.json();

      if (data.Status !== 0) {
        throw new Error('DNS 조회 중 오류가 발생했습니다.');
      }

      if (!data.Answer || data.Answer.length === 0) {
        setError('DMARC 레코드를 찾을 수 없습니다. 도메인에 DMARC 레코드가 설정되어 있지 않습니다.');
        setLoading(false);
        return;
      }

      // DMARC 레코드 찾기 (v=DMARC1로 시작하는 레코드)
      const dmarcRecord = data.Answer.find(answer => 
        answer.data && answer.data.includes('v=DMARC1')
      );

      if (!dmarcRecord) {
        setError('유효한 DMARC 레코드를 찾을 수 없습니다.');
        setLoading(false);
        return;
      }

      // 따옴표 제거
      const recordText = dmarcRecord.data.replace(/"/g, '');
      const tags = parseDMARCRecord(recordText);
      const validation = validateDMARCRecord(tags, recordText);

      setResult({
        record: recordText,
        tags,
        validation,
        domain: dmarcDomain
      });
    } catch (err) {
      setError(err.message || '오류가 발생했습니다.');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      checkDMARC();
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-4">
      <div className="max-w-4xl mx-auto py-8">
        {/* 헤더 */}
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-800 mb-2">
            DMARC 레코드 검색기
          </h1>
          <p className="text-gray-600">
            도메인의 DMARC 레코드를 확인하고 검증하세요
          </p>
        </div>

        {/* 검색 입력 */}
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <div className="flex gap-3">
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="example.com"
              className="flex-1 px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
            />
            <button
              onClick={checkDMARC}
              disabled={loading}
              className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center gap-2 font-medium transition-colors"
            >
              <Search size={20} />
              {loading ? '조회 중...' : '검색'}
            </button>
          </div>
        </div>

        {/* 오류 메시지 */}
        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
            <div className="flex items-start gap-3">
              <XCircle className="text-red-600 flex-shrink-0" size={24} />
              <div>
                <h3 className="font-semibold text-red-800 mb-1">오류</h3>
                <p className="text-red-700">{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* 결과 */}
        {result && (
          <div className="space-y-6">
            {/* DMARC 레코드 */}
            <div className="bg-white rounded-lg shadow-lg p-6">
              <h2 className="text-xl font-bold text-gray-800 mb-4 flex items-center gap-2">
                <CheckCircle className="text-green-600" size={24} />
                DMARC Record
              </h2>
              <div className="bg-gray-50 rounded p-4 mb-4">
                <p className="text-sm text-gray-600 mb-2">도메인: {result.domain}</p>
                <code className="text-sm text-gray-800 break-all">
                  {result.record}
                </code>
              </div>
            </div>

            {/* 태그 분석 - 사용된 태그만 */}
            <div className="bg-white rounded-lg shadow-lg p-6">
              <h2 className="text-xl font-bold text-gray-800 mb-4">Record Checks</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {Object.entries(result.tags).map(([key, tagData]) => (
                  <div key={key} className="bg-gray-50 rounded p-4 border-l-4 border-green-500">
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-semibold text-blue-600">{key}</span>
                        <CheckCircle className="text-green-600" size={16} />
                      </div>
                      {key === 'p' && (
                        <span className={`text-sm font-medium ${getPolicyColor(tagData.value)}`}>
                          {tagData.value.toUpperCase()}
                        </span>
                      )}
                    </div>
                    <p className="text-gray-700 font-mono text-sm mb-2">{tagData.value}</p>
                    {DMARC_TAGS[key] && (
                      <p className="text-sm text-gray-600">
                        {DMARC_TAGS[key].description}
                      </p>
                    )}
                  </div>
                ))}
              </div>

              {/* 미사용 태그 표시 */}
              <div className="mt-6 pt-6 border-t border-gray-200">
                <h3 className="text-lg font-semibold text-gray-700 mb-3">미사용 태그 (기본값 적용)</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {Object.entries(DMARC_TAGS)
                    .filter(([key]) => !result.tags[key])
                    .map(([key, tagInfo]) => (
                      <div key={key} className="bg-gray-50 rounded p-4 border-l-4 border-gray-300 opacity-75">
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-semibold text-gray-500">{key}</span>
                            <XCircle className="text-gray-400" size={16} />
                          </div>
                          {tagInfo.required && (
                            <span className="text-xs font-medium text-red-600 bg-red-100 px-2 py-1 rounded">
                              필수
                            </span>
                          )}
                        </div>
                        <p className="text-sm text-gray-500 mb-2">
                          {tagInfo.name}
                        </p>
                        <p className="text-sm text-gray-600 mb-2">
                          {tagInfo.description}
                        </p>
                        {tagInfo.default && (
                          <p className="text-xs text-gray-500 mt-1">
                            기본값: <span className="font-mono">{tagInfo.default}</span>
                          </p>
                        )}
                      </div>
                    ))}
                </div>
              </div>
            </div>

            {/* Tags Found - 모든 태그 설명 */}
            <div className="bg-white rounded-lg shadow-lg p-6">
              <h2 className="text-xl font-bold text-gray-800 mb-4">Tags Found</h2>
              <div className="space-y-3">
                {Object.entries(DMARC_TAGS).map(([key, tagInfo]) => {
                  const isUsed = !!result.tags[key];
                  return (
                    <div
                      key={key}
                      className={`p-4 rounded-lg border ${
                        isUsed
                          ? 'bg-green-50 border-green-200'
                          : 'bg-gray-50 border-gray-200'
                      }`}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-mono font-bold text-gray-800">{key}</span>
                            <span className="text-sm text-gray-600">- {tagInfo.name}</span>
                            {tagInfo.required && (
                              <span className="text-xs font-medium text-red-600 bg-red-100 px-2 py-1 rounded">
                                필수
                              </span>
                            )}
                            {isUsed && (
                              <CheckCircle className="text-green-600" size={18} />
                            )}
                          </div>
                          <p className="text-sm text-gray-700 mb-2">{tagInfo.description}</p>
                          {isUsed ? (
                            <div className="flex items-center gap-2">
                              <span className="text-xs text-gray-600">현재 값:</span>
                              <code className="text-xs bg-white px-2 py-1 rounded border border-gray-200">
                                {result.tags[key].value}
                              </code>
                            </div>
                          ) : (
                            tagInfo.default && (
                              <p className="text-xs text-gray-500">
                                기본값: <code className="bg-white px-2 py-1 rounded border border-gray-200">{tagInfo.default}</code>
                              </p>
                            )
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* 검증 결과 */}
            {(result.validation.issues.length > 0 || result.validation.recommendations.length > 0) && (
              <div className="bg-white rounded-lg shadow-lg p-6">
                <h2 className="text-xl font-bold text-gray-800 mb-4">검증 결과</h2>
                
                {result.validation.issues.length > 0 && (
                  <div className="mb-4">
                    <h3 className="font-semibold text-red-700 mb-2 flex items-center gap-2">
                      <XCircle size={20} />
                      문제점
                    </h3>
                    <ul className="space-y-2">
                      {result.validation.issues.map((issue, idx) => (
                        <li key={idx} className="flex items-start gap-2 text-red-600">
                          <span className="mt-1">•</span>
                          <span>{issue}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {result.validation.recommendations.length > 0 && (
                  <div>
                    <h3 className="font-semibold text-yellow-700 mb-2 flex items-center gap-2">
                      <AlertTriangle size={20} />
                      권장사항
                    </h3>
                    <ul className="space-y-2">
                      {result.validation.recommendations.map((rec, idx) => (
                        <li key={idx} className="flex items-start gap-2 text-yellow-700">
                          <span className="mt-1">•</span>
                          <span>{rec}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {/* 정보 박스 */}
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
              <div className="flex items-start gap-3">
                <Info className="text-blue-600 flex-shrink-0 mt-1" size={24} />
                <div>
                  <h3 className="font-semibold text-blue-800 mb-2">DMARC란?</h3>
                  <p className="text-blue-700 text-sm mb-2">
                    DMARC(Domain-based Message Authentication, Reporting and Conformance)는 
                    이메일 인증 프로토콜로, 도메인 스푸핑 및 피싱 공격을 방지합니다.
                  </p>
                  <p className="text-blue-700 text-sm">
                    DMARC는 SPF 및 DKIM과 함께 작동하여 이메일 발신자의 신원을 확인하고 
                    무단 사용을 방지합니다.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* 예시 도메인 */}
        {!result && !error && (
          <div className="bg-white rounded-lg shadow-lg p-6">
            <h3 className="font-semibold text-gray-800 mb-3">테스트해볼 도메인 예시:</h3>
            <div className="flex flex-wrap gap-2">
              {['google.com', 'microsoft.com', 'facebook.com', 'amazon.com'].map(d => (
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
