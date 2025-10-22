import React, { useState } from 'react';
import { Search, CheckCircle, XCircle, AlertTriangle, Info } from 'lucide-react';

// DKIM 태그 정의 (RFC 6376)
const DKIM_TAGS = {
  v: {
    name: 'Version',
    description: 'DKIM 버전',
    required: false,
    default: 'DKIM1',
    translation: 'Version of the DKIM key record (plain-text; RECOMMENDED). This tag MUST be the first tag in the record if present. Warning: some ISPs may mark the DKIM authentication check as neutral if the version tag is invalid.'
  },
  h: {
    name: 'Hash algorithms',
    description: '허용되는 해시 알고리즘',
    required: false,
    default: '* (allow all)',
    translation: 'Acceptable hash algorithms (plain-text; OPTIONAL). A colon-separated list of hash algorithms that might be used. Unrecognized algorithms MUST be ignored. The currently recognized algorithms are "sha1" and "sha256".'
  },
  k: {
    name: 'Key type',
    description: '공개키 알고리즘 타입',
    required: false,
    default: 'rsa',
    translation: 'Key type (plain-text; OPTIONAL). Unrecognized key types MUST be ignored. Supported values: "rsa", "ed25519".'
  },
  n: {
    name: 'Notes',
    description: '관리자를 위한 노트',
    required: false,
    default: '(empty)',
    translation: 'Notes that might be of interest to a human (OPTIONAL). Not interpreted in any way.'
  },
  p: {
    name: 'Public key',
    description: 'Base64로 인코딩된 공개키',
    required: true,
    default: '(none)',
    translation: 'Public-key data (base64; REQUIRED). An empty value means that this public key has been revoked. This is the only required tag.'
  },
  s: {
    name: 'Service type',
    description: '서비스 타입',
    required: false,
    default: '* (allow all)',
    translation: 'Service Type (plain-text; OPTIONAL). A colon-separated list of service types to which this record applies. Unrecognized service types MUST be ignored. Currently only "email" is recognized.'
  },
  t: {
    name: 'Flags',
    description: 'DKIM 플래그 (y=testing, s=strict)',
    required: false,
    default: '(no flags set)',
    translation: 'Flags (plain-text; OPTIONAL). A colon-separated list of names. Unrecognized flags MUST be ignored. The defined flags are as follows: "y" – this domain is testing DKIM (test mode), "s" – verifiers MUST check for domain alignment (strict mode).'
  },
  g: {
    name: 'Granularity',
    description: '키 세분성 (local-part)',
    required: false,
    default: '*',
    translation: 'Granularity of the key (plain-text; OPTIONAL). This value is a string that represents a pattern for matching local parts. If not specified, the default value is "*", which matches all addresses.'
  }
};

// Base64 디코딩 및 공개키 길이 계산
const getPublicKeyLength = (base64Key) => {
  try {
    // Base64 디코딩
    const binaryString = atob(base64Key);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    // RSA 공개키의 경우, 모듈러스 길이를 찾아야 함
    // ASN.1 DER 인코딩된 RSA 공개키 파싱은 복잡하므로
    // 근사치로 바이트 길이 * 8을 사용
    // 실제로는 더 정확한 파싱이 필요하지만, 여기서는 간단히 처리

    // 일반적인 RSA 키 길이 추정
    const byteLength = bytes.length;
    if (byteLength >= 290 && byteLength <= 300) return 2048;
    if (byteLength >= 540 && byteLength <= 550) return 4096;
    if (byteLength >= 130 && byteLength <= 150) return 1024;
    if (byteLength >= 250 && byteLength <= 270) return 2048;

    // 기본 계산
    return Math.floor(byteLength * 6.5); // Base64는 대략 6비트 per character
  } catch (e) {
    return null;
  }
};

// DKIM 레코드 파싱
const parseDKIMRecord = (record) => {
  const tags = {};
  const pairs = record.split(';').map(p => p.trim()).filter(p => p);

  pairs.forEach((pair) => {
    const [key, ...valueParts] = pair.split('=');
    const value = valueParts.join('=').trim(); // p 태그의 경우 = 기호가 있을 수 있음
    if (key && value) {
      tags[key.trim()] = value;
    }
  });

  return tags;
};

// DKIM 레코드 검증
const validateDKIMRecord = (tags) => {
  const errors = [];
  const warnings = [];

  // v 태그 검증
  if (tags.v && tags.v !== 'DKIM1') {
    errors.push(`v 태그 값이 올바르지 않습니다: ${tags.v}. DKIM1이어야 합니다.`);
  }

  // p 태그 검증 (필수)
  if (!tags.p) {
    errors.push('p 태그(공개키)가 없습니다. 필수 태그입니다.');
  } else if (tags.p === '') {
    warnings.push('공개키가 비어있습니다. 이 키는 취소된 것입니다.');
  } else {
    // Base64 형식 검증
    const base64Regex = /^[A-Za-z0-9+/=]+$/;
    if (!base64Regex.test(tags.p)) {
      errors.push('공개키가 올바른 Base64 형식이 아닙니다.');
    } else {
      // 공개키 길이 검증
      const keyLength = getPublicKeyLength(tags.p);
      if (keyLength && keyLength < 1024) {
        warnings.push(`공개키 길이가 너무 짧습니다 (${keyLength} 비트). 최소 1024비트 권장합니다.`);
      } else if (keyLength && keyLength === 1024) {
        warnings.push('공개키 길이가 1024비트입니다. 보안 강화를 위해 2048비트 이상을 권장합니다.');
      }
    }
  }

  // k 태그 검증
  if (tags.k && !['rsa', 'ed25519'].includes(tags.k)) {
    warnings.push(`알 수 없는 키 타입: ${tags.k}. rsa 또는 ed25519를 사용하세요.`);
  }

  // h 태그 검증
  if (tags.h) {
    const hashAlgos = tags.h.split(':');
    const validAlgos = ['sha1', 'sha256'];
    const invalidAlgos = hashAlgos.filter(algo => !validAlgos.includes(algo));
    if (invalidAlgos.length > 0) {
      warnings.push(`알 수 없는 해시 알고리즘: ${invalidAlgos.join(', ')}`);
    }
    if (hashAlgos.includes('sha1') && !hashAlgos.includes('sha256')) {
      warnings.push('SHA-1은 더 이상 권장되지 않습니다. SHA-256을 사용하세요.');
    }
  }

  // t 태그 검증 (테스트 모드)
  if (tags.t) {
    const flags = tags.t.split(':');
    if (flags.includes('y')) {
      warnings.push('이 키는 테스트 모드입니다 (t=y). 프로덕션에서는 제거하세요.');
    }
    if (flags.includes('s')) {
      warnings.push('strict 모드가 활성화되어 있습니다 (t=s). 도메인과 로컬 파트가 정확히 일치해야 합니다.');
    }
  }

  // s 태그 검증
  if (tags.s && tags.s !== '*' && tags.s !== 'email') {
    warnings.push(`알 수 없는 서비스 타입: ${tags.s}`);
  }

  return { errors, warnings };
};

export default function DKIMChecker() {
  const [domain, setDomain] = useState('');
  const [selector, setSelector] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const checkDKIM = async (e) => {
    e.preventDefault();

    if (!domain.trim() || !selector.trim()) {
      setError('도메인과 셀렉터를 모두 입력해주세요.');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      // DKIM 레코드 조회: selector._domainkey.domain
      const dkimDomain = `${selector.trim()}._domainkey.${domain.trim()}`;
      const response = await fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(dkimDomain)}&type=TXT`
      );

      if (!response.ok) {
        throw new Error('DNS 조회에 실패했습니다.');
      }

      const data = await response.json();

      if (data.Status !== 0) {
        throw new Error('DNS 조회 중 오류가 발생했습니다.');
      }

      if (!data.Answer || data.Answer.length === 0) {
        setError(`DKIM 레코드를 찾을 수 없습니다. 셀렉터가 올바른지 확인하세요.\n조회: ${dkimDomain}`);
        setLoading(false);
        return;
      }

      // DKIM 레코드 찾기 (v=DKIM1로 시작하거나 p= 태그가 있는 레코드)
      const dkimRecord = data.Answer.find(answer =>
        answer.data && (answer.data.includes('v=DKIM1') || answer.data.includes('p='))
      );

      if (!dkimRecord) {
        setError(`유효한 DKIM 레코드를 찾을 수 없습니다.\n조회: ${dkimDomain}`);
        setLoading(false);
        return;
      }

      // 따옴표 제거 및 공백 제거
      const recordText = dkimRecord.data.replace(/"/g, '').replace(/\s+/g, '');
      const tags = parseDKIMRecord(recordText);
      const validation = validateDKIMRecord(tags);

      // 공개키 길이 계산
      const publicKeyLength = tags.p ? getPublicKeyLength(tags.p) : null;

      setResult({
        query: dkimDomain,
        record: recordText,
        tags,
        validation,
        publicKeyLength,
        isValid: validation.errors.length === 0
      });
    } catch (err) {
      setError(err.message || '오류가 발생했습니다.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-50 to-pink-100 p-4">
      <div className="max-w-5xl mx-auto py-8">
        {/* 헤더 */}
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-800 mb-2">
            DKIM 레코드 검색기
          </h1>
          <p className="text-gray-600">
            도메인의 DKIM 레코드를 확인하고 검증하세요
          </p>
        </div>

        {/* 검색 입력 */}
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <form onSubmit={checkDKIM} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  도메인
                </label>
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="example.com"
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent outline-none"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  셀렉터
                </label>
                <input
                  type="text"
                  value={selector}
                  onChange={(e) => setSelector(e.target.value)}
                  placeholder="default"
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent outline-none"
                />
              </div>
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full px-6 py-3 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center justify-center gap-2 font-medium transition-colors"
            >
              <Search size={20} />
              {loading ? '조회 중...' : 'Inspect DKIM'}
            </button>
          </form>

          {/* 일반적인 셀렉터 힌트 */}
          <div className="mt-4 p-4 bg-blue-50 border border-blue-200 rounded-lg">
            <div className="flex items-start gap-2">
              <Info className="text-blue-600 flex-shrink-0 mt-0.5" size={18} />
              <div className="text-sm text-blue-800">
                <p className="font-semibold mb-1">일반적인 DKIM 셀렉터:</p>
                <p className="text-blue-700">
                  default, google, s1, s2, k1, selector1, selector2, dkim, mail 등
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* 오류 메시지 */}
        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
            <div className="flex items-start gap-3">
              <XCircle className="text-red-600 flex-shrink-0" size={24} />
              <div>
                <h3 className="font-semibold text-red-800 mb-1">오류</h3>
                <p className="text-red-700 whitespace-pre-line">{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* 결과 */}
        {result && (
          <div className="space-y-6">
            {/* 성공/실패 메시지 */}
            {result.isValid ? (
              <div className="bg-green-50 border border-green-200 rounded-lg p-6">
                <div className="flex items-start gap-3">
                  <CheckCircle className="text-green-600 flex-shrink-0" size={24} />
                  <div>
                    <h3 className="font-semibold text-green-800 text-lg mb-1">
                      축하합니다! DKIM 레코드가 유효합니다.
                    </h3>
                  </div>
                </div>
              </div>
            ) : (
              <div className="bg-red-50 border border-red-200 rounded-lg p-6">
                <div className="flex items-start gap-3">
                  <XCircle className="text-red-600 flex-shrink-0" size={24} />
                  <div>
                    <h3 className="font-semibold text-red-800 text-lg mb-1">
                      DKIM 레코드에 문제가 있습니다.
                    </h3>
                  </div>
                </div>
              </div>
            )}

            {/* Query 정보 */}
            <div className="bg-white rounded-lg shadow-lg p-6">
              <p className="text-sm text-gray-600 mb-4">
                <span className="font-semibold">Query:</span> {result.query}
              </p>

              <h3 className="text-xl font-bold text-gray-800 mb-4">DKIM 레코드</h3>
              <div className="bg-gray-50 rounded-lg p-4 mb-4">
                <code className="text-sm text-gray-800 break-all font-mono">
                  {result.record}
                </code>
              </div>

              {/* 공개키 길이 */}
              {result.publicKeyLength && (
                <div className="bg-purple-50 border-l-4 border-purple-500 p-4 mb-4">
                  <div className="flex items-center gap-4">
                    <div>
                      <p className="text-sm font-medium text-gray-600">Public key length:</p>
                      <p className={`text-3xl font-bold ${
                        result.publicKeyLength >= 2048 ? 'text-green-600' :
                        result.publicKeyLength >= 1024 ? 'text-yellow-600' : 'text-red-600'
                      }`}>
                        {result.publicKeyLength}
                      </p>
                    </div>
                    <div className="text-sm text-gray-600">
                      {result.publicKeyLength >= 2048 ? (
                        <p className="text-green-700">권장 키 길이입니다.</p>
                      ) : result.publicKeyLength >= 1024 ? (
                        <p className="text-yellow-700">2048비트 이상을 권장합니다.</p>
                      ) : (
                        <p className="text-red-700">키 길이가 너무 짧습니다.</p>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* 에러 및 경고 */}
            {(result.validation.errors.length > 0 || result.validation.warnings.length > 0) && (
              <div className="bg-white rounded-lg shadow-lg p-6">
                <h3 className="text-xl font-bold text-gray-800 mb-4">검증 결과</h3>

                {result.validation.errors.length > 0 && (
                  <div className="mb-4">
                    <h4 className="font-semibold text-red-700 mb-2 flex items-center gap-2">
                      <XCircle size={20} />
                      에러
                    </h4>
                    <ul className="space-y-2">
                      {result.validation.errors.map((err, idx) => (
                        <li key={idx} className="flex items-start gap-2 text-red-600">
                          <span className="mt-1">•</span>
                          <span>{err}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {result.validation.warnings.length > 0 && (
                  <div>
                    <h4 className="font-semibold text-yellow-700 mb-2 flex items-center gap-2">
                      <AlertTriangle size={20} />
                      경고
                    </h4>
                    <ul className="space-y-2">
                      {result.validation.warnings.map((warn, idx) => (
                        <li key={idx} className="flex items-start gap-2 text-yellow-700">
                          <span className="mt-1">•</span>
                          <span>{warn}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {/* Legend - 태그 상세 정보 */}
            <div className="bg-white rounded-lg shadow-lg p-6">
              <h3 className="text-xl font-bold text-gray-800 mb-4">Legend</h3>
              <h4 className="text-lg font-semibold text-gray-700 mb-3">Details</h4>

              <div className="overflow-x-auto">
                <table className="min-w-full border border-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-4 py-3 text-left text-sm font-semibold text-gray-700 border-b w-12">
                        상태
                      </th>
                      <th className="px-4 py-3 text-left text-sm font-semibold text-gray-700 border-b w-16">
                        Tag
                      </th>
                      <th className="px-4 py-3 text-left text-sm font-semibold text-gray-700 border-b w-32">
                        Name
                      </th>
                      <th className="px-4 py-3 text-left text-sm font-semibold text-gray-700 border-b">
                        Value
                      </th>
                      <th className="px-4 py-3 text-left text-sm font-semibold text-gray-700 border-b">
                        Default
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white">
                    {Object.entries(DKIM_TAGS).map(([key, tagInfo]) => {
                      const hasValue = result.tags[key] !== undefined;
                      const value = hasValue ? result.tags[key] : null;
                      const isError = tagInfo.required && !hasValue;

                      return (
                        <tr key={key} className="border-b border-gray-200 hover:bg-gray-50">
                          <td className="px-4 py-3">
                            {hasValue ? (
                              <CheckCircle className="text-green-600" size={20} />
                            ) : isError ? (
                              <XCircle className="text-red-600" size={20} />
                            ) : (
                              <div className="w-5 h-5 border-2 border-gray-300 rounded-full"></div>
                            )}
                          </td>
                          <td className="px-4 py-3 font-mono font-semibold text-gray-800">
                            {key}
                          </td>
                          <td className="px-4 py-3 text-sm text-gray-700">
                            {tagInfo.name}
                          </td>
                          <td className="px-4 py-3 text-sm text-gray-800 break-all">
                            {hasValue ? (
                              <span className="font-mono">
                                {key === 'p' && value.length > 50
                                  ? `${value.substring(0, 50)}...`
                                  : value}
                              </span>
                            ) : (
                              <span className="text-gray-400 italic">미설정</span>
                            )}
                          </td>
                          <td className="px-4 py-3 text-sm text-gray-500">
                            <span className="flex items-center gap-1">
                              <Info size={14} className="text-gray-400" />
                              {tagInfo.default}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* 공개키 전체 표시 */}
              {result.tags.p && (
                <div className="mt-6">
                  <h4 className="text-sm font-semibold text-gray-700 mb-2">전체 공개키 (p 태그):</h4>
                  <div className="bg-gray-50 rounded-lg p-4">
                    <code className="text-xs text-gray-800 break-all font-mono leading-relaxed">
                      {result.tags.p}
                    </code>
                  </div>
                </div>
              )}
            </div>

            {/* RFC 6376 태그 상세 설명 */}
            <div className="bg-white rounded-lg shadow-lg p-6">
              <div className="bg-green-50 border border-green-200 rounded-lg p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-xl font-bold text-gray-800">Legend</h3>
                </div>

                <h4 className="text-lg font-semibold text-gray-700 mb-4">RFC 6376 Tag Details</h4>

                <div className="overflow-x-auto">
                  <table className="min-w-full border border-gray-300">
                    <thead className="bg-gray-100">
                      <tr className="text-center">
                        <th className="px-4 py-3 text-sm font-bold text-gray-700 border-b border-r border-gray-300 w-20">
                          TAG
                        </th>
                        <th className="px-4 py-3 text-sm font-bold text-gray-700 border-b border-r border-gray-300 w-32">
                          NAME
                        </th>
                        <th className="px-4 py-3 text-sm font-bold text-gray-700 border-b border-r border-gray-300 w-32">
                          DEFAULT
                        </th>
                        <th className="px-4 py-3 text-sm font-bold text-gray-700 border-b border-gray-300">
                          TRANSLATION
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white">
                      {['v', 'h', 'k', 'n', 'p', 's', 't'].map((tagKey) => {
                        const tag = DKIM_TAGS[tagKey];
                        return (
                          <tr key={tagKey} className="border-b border-gray-200 hover:bg-gray-50">
                            <td className="px-4 py-3 text-sm font-mono font-semibold text-gray-800 border-r border-gray-200">
                              {tagKey}
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-700 border-r border-gray-200">
                              {tag.name}
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-600 border-r border-gray-200">
                              {tag.default}
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-700 leading-relaxed">
                              {tag.translation}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            {/* 정보 박스 */}
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
              <div className="flex items-start gap-3">
                <Info className="text-blue-600 flex-shrink-0 mt-1" size={24} />
                <div>
                  <h3 className="font-semibold text-blue-800 mb-2">DKIM이란?</h3>
                  <p className="text-blue-700 text-sm mb-2">
                    DKIM(DomainKeys Identified Mail)은 이메일 메시지가 전송 중에
                    변조되지 않았음을 확인하는 이메일 인증 방법입니다.
                  </p>
                  <p className="text-blue-700 text-sm">
                    발신 서버는 개인키로 이메일에 서명하고, 수신 서버는 DNS에 게시된
                    공개키로 서명을 확인합니다.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* 예시 */}
        {!result && !error && (
          <div className="bg-white rounded-lg shadow-lg p-6">
            <h3 className="font-semibold text-gray-800 mb-3">테스트해볼 예시:</h3>
            <div className="space-y-2">
              <div className="flex items-center gap-4">
                <button
                  onClick={() => {
                    setDomain('nhn.com');
                    setSelector('toast');
                  }}
                  className="px-4 py-2 bg-gray-100 hover:bg-gray-200 rounded-lg text-gray-700 text-sm transition-colors"
                >
                  nhn.com (toast)
                </button>
                <button
                  onClick={() => {
                    setDomain('google.com');
                    setSelector('google');
                  }}
                  className="px-4 py-2 bg-gray-100 hover:bg-gray-200 rounded-lg text-gray-700 text-sm transition-colors"
                >
                  google.com (google)
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
