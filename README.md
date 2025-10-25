# #11 해시 생성기

> ⚠️ **개발 시작 전 필독!**
> 전역 개발 가이드: [`../_template/README.md`](../_template/README.md)
> Phase 1 버그, 체크리스트, 크로스 프로모션 도구 버튼 구현 확인 필수!

**URL:** hash.baal.co.kr

## 서비스 내용

MD5, SHA-1, SHA-256 해시 생성. 파일/텍스트 지원

## 기능 요구사항

- [ ] 텍스트 해시 생성
- [ ] 파일 해시 생성 (드래그 앤 드롭)
- [ ] 알고리즘 선택:
  - [ ] MD5
  - [ ] SHA-1
  - [ ] SHA-256
  - [ ] SHA-512
  - [ ] SHA-384
- [ ] 복사 버튼
- [ ] 해시 비교 기능 (검증)
- [ ] 대소문자 변환 (uppercase/lowercase)
- [ ] 진행률 표시 (대용량 파일)
- [ ] 다중 알고리즘 동시 생성

## 경쟁사 분석 (2025년 기준)

### 인기 사이트 TOP 5

1. **MD5File** - 파일 해시 전문
   - 강점: 빠른 속도, MD5/SHA 지원
   - 약점: UI 구식, 광고 많음

2. **Online Hash Calculator** - 다양한 알고리즘
   - 강점: 20+ 알고리즘 지원 (MD5, SHA, BLAKE2 등)
   - 약점: 복잡한 UI

3. **Hash Generator** - 간단한 UI
   - 강점: 빠르고 간단
   - 약점: 기능 제한적

4. **Emn178 Online Tools** - 개발자 전문
   - 강점: 여러 해시 동시 생성
   - 약점: 디자인 부족

5. **CyberChef** - 통합 도구
   - 강점: 해시 외 다양한 인코딩/암호화 기능
   - 약점: 복잡함, 초보자 어려움

### 우리의 차별화 전략

- ✅ **여러 알고리즘 동시 생성** - 한 번에 모든 해시 확인
- ✅ **해시 검증** - 기존 해시와 비교
- ✅ **대용량 파일 지원** - 진행률 표시
- ✅ **드래그 앤 드롭** - 파일 쉽게 업로드
- ✅ **다크모드** 지원
- ✅ **한/영 전환**
- ✅ **완전 무료** - 광고 없음

## 주요 라이브러리

### 옵션 1: Web Crypto API (추천!)

브라우저 내장 암호화 API

```javascript
// SHA-256 해시 생성
async function generateHash(algorithm, data) {
  // 알고리즘 매핑
  const algoMap = {
    'md5': 'MD5',           // ❌ Web Crypto API는 MD5 미지원!
    'sha-1': 'SHA-1',
    'sha-256': 'SHA-256',
    'sha-384': 'SHA-384',
    'sha-512': 'SHA-512'
  };

  try {
    // 텍스트 → ArrayBuffer
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);

    // 해시 생성
    const hashBuffer = await crypto.subtle.digest(
      algoMap[algorithm],
      dataBuffer
    );

    // ArrayBuffer → Hex 문자열
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('');

    return hashHex;
  } catch (error) {
    throw new Error(`해시 생성 실패: ${error.message}`);
  }
}

// 사용 예시
const hash = await generateHash('sha-256', 'Hello World');
console.log(hash); // "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
```

### 파일 해시 생성

```javascript
async function generateFileHash(algorithm, file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();

    reader.onload = async (e) => {
      try {
        const arrayBuffer = e.target.result;
        const hashBuffer = await crypto.subtle.digest(
          algorithm.toUpperCase(),
          arrayBuffer
        );

        // ArrayBuffer → Hex
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray
          .map(byte => byte.toString(16).padStart(2, '0'))
          .join('');

        resolve(hashHex);
      } catch (error) {
        reject(error);
      }
    };

    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });
}

// 사용
const file = document.querySelector('input[type="file"]').files[0];
const hash = await generateFileHash('SHA-256', file);
console.log(hash);
```

### 대용량 파일 청크 처리 (진행률 표시)

```javascript
async function generateFileHashWithProgress(algorithm, file, onProgress) {
  const chunkSize = 1024 * 1024; // 1MB
  const chunks = Math.ceil(file.size / chunkSize);
  let currentChunk = 0;

  // Web Crypto API는 스트리밍 불가능
  // 전체 파일을 한 번에 처리해야 함
  return new Promise((resolve, reject) => {
    const reader = new FileReader();

    reader.onprogress = (e) => {
      if (e.lengthComputable) {
        const progress = Math.round((e.loaded / e.total) * 100);
        onProgress(progress);
      }
    };

    reader.onload = async (e) => {
      try {
        const arrayBuffer = e.target.result;
        const hashBuffer = await crypto.subtle.digest(
          algorithm,
          arrayBuffer
        );

        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray
          .map(byte => byte.toString(16).padStart(2, '0'))
          .join('');

        resolve(hashHex);
      } catch (error) {
        reject(error);
      }
    };

    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });
}

// 사용
const hash = await generateFileHashWithProgress('SHA-256', file, (progress) => {
  console.log(`진행률: ${progress}%`);
  updateProgressBar(progress);
});
```

### 옵션 2: CryptoJS (MD5 지원)

Web Crypto API는 MD5 미지원이므로 CryptoJS 사용

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js"></script>
```

```javascript
// MD5
const md5Hash = CryptoJS.MD5('Hello World').toString();
console.log(md5Hash); // "b10a8db164e0754105b7a99be72e3fe5"

// SHA-256
const sha256Hash = CryptoJS.SHA256('Hello World').toString();
console.log(sha256Hash); // "a591a6d40bf420404a011733cfb7b190..."

// SHA-512
const sha512Hash = CryptoJS.SHA512('Hello World').toString();
console.log(sha512Hash);

// 파일 해시 (청크 처리)
function generateFileHashCryptoJS(file, algorithm, onProgress) {
  return new Promise((resolve, reject) => {
    const chunkSize = 1024 * 1024; // 1MB
    const chunks = Math.ceil(file.size / chunkSize);
    let currentChunk = 0;

    // 알고리즘 선택
    const hashAlgorithm = {
      'MD5': CryptoJS.algo.MD5.create(),
      'SHA1': CryptoJS.algo.SHA1.create(),
      'SHA256': CryptoJS.algo.SHA256.create(),
      'SHA512': CryptoJS.algo.SHA512.create()
    }[algorithm];

    const reader = new FileReader();

    reader.onload = (e) => {
      // WordArray로 변환
      const wordArray = CryptoJS.lib.WordArray.create(e.target.result);
      hashAlgorithm.update(wordArray);

      currentChunk++;

      if (currentChunk < chunks) {
        // 다음 청크 읽기
        loadNextChunk();
        onProgress(Math.round((currentChunk / chunks) * 100));
      } else {
        // 마지막 청크, 해시 완성
        const hash = hashAlgorithm.finalize().toString();
        onProgress(100);
        resolve(hash);
      }
    };

    reader.onerror = reject;

    function loadNextChunk() {
      const start = currentChunk * chunkSize;
      const end = Math.min(start + chunkSize, file.size);
      const blob = file.slice(start, end);
      reader.readAsArrayBuffer(blob);
    }

    loadNextChunk();
  });
}
```

### 해시 검증 (비교)

```javascript
function verifyHash(generatedHash, expectedHash) {
  // 대소문자 무시, 공백 제거
  const generated = generatedHash.toLowerCase().replace(/\s/g, '');
  const expected = expectedHash.toLowerCase().replace(/\s/g, '');

  const isMatch = generated === expected;

  return {
    isMatch,
    generated,
    expected,
    message: isMatch
      ? '✓ 해시가 일치합니다.'
      : '✗ 해시가 일치하지 않습니다.'
  };
}

// 사용
const result = verifyHash(
  'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e',
  'A591A6D40BF420404A011733CFB7B190D62C65BF0BCDA32B57B277D9AD9F146E'
);
console.log(result.message); // "✓ 해시가 일치합니다."
```

## UI/UX 디자인 패턴

### 화면 구성

```
┌─────────────────────────────────────────────┐
│  해시 생성기 (Hash Generator)                │
│  파일과 텍스트의 해시값을 생성하세요          │
├─────────────────────────────────────────────┤
│  모드: [텍스트] [파일]                       │
├─────────────────────────────────────────────┤
│  ┌─ 텍스트 모드 ──────────────────────┐    │
│  │                                     │    │
│  │  텍스트 입력:                        │    │
│  │  ┌─────────────────────────────┐   │    │
│  │  │ Hello World                 │   │    │
│  │  └─────────────────────────────┘   │    │
│  │                                     │    │
│  │  알고리즘:                           │    │
│  │  ☑ MD5                              │    │
│  │  ☑ SHA-1                            │    │
│  │  ☑ SHA-256                          │    │
│  │  ☑ SHA-384                          │    │
│  │  ☑ SHA-512                          │    │
│  │                                     │    │
│  │  [해시 생성]                         │    │
│  └─────────────────────────────────────┘    │
│                                             │
│  결과:                                      │
│  ┌─────────────────────────────────────┐   │
│  │ MD5:                                │   │
│  │ b10a8db164e0754105b7a99be72e3fe5   │   │
│  │ [복사] [대문자로]                     │   │
│  │                                     │   │
│  │ SHA-1:                              │   │
│  │ 0a4d55a8d778e5022fab701977c5d840... │   │
│  │ [복사] [대문자로]                     │   │
│  │                                     │   │
│  │ SHA-256:                            │   │
│  │ a591a6d40bf420404a011733cfb7b190... │   │
│  │ [복사] [대문자로]                     │   │
│  └─────────────────────────────────────┘   │
│                                             │
│  ┌─ 해시 검증 ────────────────────────┐    │
│  │  예상 해시 (선택사항):               │    │
│  │  ┌─────────────────────────────┐   │    │
│  │  │ b10a8db164e0754105b7a99b... │   │    │
│  │  └─────────────────────────────┘   │    │
│  │  ✓ 해시가 일치합니다!                │    │
│  └─────────────────────────────────────┘    │
│                                             │
│  ┌─ 파일 모드 ─────────────────────────┐   │
│  │  🗂️ 드래그 앤 드롭 또는 클릭         │   │
│  │                                     │   │
│  │  선택된 파일: document.pdf (2.5MB)  │   │
│  │  ▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░ 50%          │   │
│  └─────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

### 해시 알고리즘 설명

| 알고리즘 | 길이 | 속도 | 용도 | 보안성 |
|----------|------|------|------|--------|
| MD5 | 128bit (32자) | 빠름 | 체크섬 | ⚠️ 취약 |
| SHA-1 | 160bit (40자) | 빠름 | Git | ⚠️ 취약 |
| SHA-256 | 256bit (64자) | 중간 | 추천 | ✓ 안전 |
| SHA-384 | 384bit (96자) | 느림 | 고보안 | ✓ 안전 |
| SHA-512 | 512bit (128자) | 느림 | 고보안 | ✓ 안전 |

## 난이도 & 예상 기간

- **난이도:** 쉬움
- **예상 기간:** 1일
- **실제 기간:** (작업 후 기록)

## 개발 일정

- [ ] 오전 1: UI 구성 (텍스트/파일 모드)
- [ ] 오전 2: 텍스트 해시 생성 (Web Crypto API + CryptoJS)
- [ ] 오후 1: 파일 해시 생성, 진행률 표시
- [ ] 오후 2: 해시 검증, 복사 기능
- [ ] 오후 3: 다중 알고리즘 동시 생성, 최적화

## 트래픽 예상

⭐⭐ 중간 - 개발자, 보안 전문가 타겟

## SEO 키워드

- 해시 생성
- MD5 생성
- SHA256 생성
- Hash Generator
- 파일 해시
- 해시 검증
- Checksum
- 파일 무결성

## 이슈 & 해결방안

### 실제 문제점 (경쟁사 분석 & 실무 이슈 기반)

1. **Web Crypto API는 MD5 미지원**
   - 원인: MD5는 더 이상 안전하지 않아 브라우저에서 제외
   - 해결: CryptoJS 라이브러리로 MD5 생성
   - 코드:
     ```javascript
     async function generateHashUnified(algorithm, data) {
       if (algorithm === 'MD5') {
         // CryptoJS 사용
         return CryptoJS.MD5(data).toString();
       } else {
         // Web Crypto API 사용
         const algoMap = {
           'SHA-1': 'SHA-1',
           'SHA-256': 'SHA-256',
           'SHA-384': 'SHA-384',
           'SHA-512': 'SHA-512'
         };

         const encoder = new TextEncoder();
         const dataBuffer = encoder.encode(data);
         const hashBuffer = await crypto.subtle.digest(
           algoMap[algorithm],
           dataBuffer
         );

         const hashArray = Array.from(new Uint8Array(hashBuffer));
         return hashArray
           .map(byte => byte.toString(16).padStart(2, '0'))
           .join('');
       }
     }
     ```

2. **대용량 파일 처리 시 메모리 부족**
   - 원인: 전체 파일을 메모리에 로드
   - 해결: 청크 단위 처리 (CryptoJS)
   - 코드:
     ```javascript
     // 위의 generateFileHashCryptoJS 참고
     // 1MB 청크로 나눠서 처리
     const hash = await generateFileHashCryptoJS(
       file,
       'SHA256',
       (progress) => {
         progressBar.style.width = `${progress}%`;
       }
     );
     ```

3. **해시 생성 중 UI 멈춤 (대용량 파일)**
   - 원인: 메인 스레드 블로킹
   - 해결: Web Worker 사용
   - 코드:
     ```javascript
     // hash-worker.js
     importScripts('https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js');

     self.onmessage = async (e) => {
       const { algorithm, data } = e.data;

       try {
         let hash;

         if (algorithm === 'MD5') {
           hash = CryptoJS.MD5(data).toString();
         } else {
           // Web Crypto API는 Worker에서도 사용 가능
           const encoder = new TextEncoder();
           const dataBuffer = encoder.encode(data);
           const hashBuffer = await crypto.subtle.digest(
             algorithm,
             dataBuffer
           );

           const hashArray = Array.from(new Uint8Array(hashBuffer));
           hash = hashArray
             .map(byte => byte.toString(16).padStart(2, '0'))
             .join('');
         }

         self.postMessage({ success: true, hash });
       } catch (error) {
         self.postMessage({ success: false, error: error.message });
       }
     };

     // 메인 스레드
     function generateHashInWorker(algorithm, data) {
       return new Promise((resolve, reject) => {
         const worker = new Worker('hash-worker.js');

         worker.onmessage = (e) => {
           worker.terminate();
           if (e.data.success) {
             resolve(e.data.hash);
           } else {
             reject(new Error(e.data.error));
           }
         };

         worker.postMessage({ algorithm, data });
       });
     }
     ```

4. **파일 타입 제한 없어서 위험**
   - 원인: 모든 파일 허용
   - 해결: 파일 크기 제한 (100MB)
   - 코드:
     ```javascript
     const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB

     function validateFile(file) {
       if (file.size > MAX_FILE_SIZE) {
         showError(`파일이 너무 큽니다. (최대 100MB, 현재 ${(file.size / 1024 / 1024).toFixed(2)}MB)`);
         return false;
       }

       return true;
     }

     fileInput.addEventListener('change', (e) => {
       const file = e.target.files[0];
       if (!file) return;

       if (!validateFile(file)) {
         fileInput.value = ''; // 초기화
         return;
       }

       generateFileHash('SHA-256', file);
     });
     ```

5. **해시 비교 시 대소문자 차이로 불일치**
   - 원인: 해시는 대소문자 구분
   - 해결: 소문자로 변환 후 비교
   - 코드:
     ```javascript
     function compareHashes(hash1, hash2) {
       // 공백 제거, 소문자 변환
       const normalized1 = hash1.toLowerCase().replace(/\s/g, '');
       const normalized2 = hash2.toLowerCase().replace(/\s/g, '');

       return normalized1 === normalized2;
     }

     // 사용
     if (compareHashes(generatedHash, userInputHash)) {
       showSuccess('✓ 해시가 일치합니다!');
     } else {
       showError('✗ 해시가 일치하지 않습니다.');
     }
     ```

6. **해시 복사 시 공백 포함**
   - 원인: 줄바꿈 있는 해시
   - 해결: 공백 제거 후 복사
   - 코드:
     ```javascript
     async function copyHashToClipboard(hash) {
       // 공백 제거
       const cleaned = hash.replace(/\s/g, '');

       try {
         await navigator.clipboard.writeText(cleaned);
         showSuccess('복사 완료!');
       } catch (error) {
         // 폴백: textarea 사용
         const textarea = document.createElement('textarea');
         textarea.value = cleaned;
         document.body.appendChild(textarea);
         textarea.select();
         document.execCommand('copy');
         document.body.removeChild(textarea);
         showSuccess('복사 완료!');
       }
     }
     ```

7. **FileReader 에러 처리 미흡**
   - 원인: 파일 읽기 실패 시 에러 표시 없음
   - 해결: onerror 핸들러 추가
   - 코드:
     ```javascript
     function readFileAsArrayBuffer(file) {
       return new Promise((resolve, reject) => {
         const reader = new FileReader();

         reader.onload = (e) => resolve(e.target.result);

         reader.onerror = () => {
           reject(new Error(`파일 읽기 실패: ${reader.error.message}`));
         };

         reader.onabort = () => {
           reject(new Error('파일 읽기 취소됨'));
         };

         reader.readAsArrayBuffer(file);
       });
     }

     // 사용
     try {
       const arrayBuffer = await readFileAsArrayBuffer(file);
       const hash = await generateHashFromArrayBuffer('SHA-256', arrayBuffer);
       showHash(hash);
     } catch (error) {
       showError(error.message);
     }
     ```

## 개발 로그

### 2025-10-25
- 프로젝트 폴더 생성
- **경쟁사 분석 완료:**
  - MD5File, Online Hash Calculator, Hash Generator 조사
  - 대부분 UI 구식, 광고 많음
  - 차별화: 다중 알고리즘 동시 생성, 해시 검증, 진행률 표시
- **라이브러리 조사 완료:**
  - Web Crypto API (SHA 계열, MD5 제외)
  - CryptoJS (MD5 포함, 모든 알고리즘)
  - Best practices: 청크 처리, Web Worker, 파일 크기 제한
- **실제 이슈 파악:**
  - MD5 미지원 (Web Crypto API)
  - 대용량 파일 메모리 부족
  - UI 멈춤 (Web Worker로 해결)
  - 해시 비교 대소문자 문제
- **UI/UX 패턴:**
  - 2가지 모드 (텍스트/파일)
  - 다중 알고리즘 동시 생성
  - 해시 검증 기능
  - 진행률 표시

## 참고 자료

- [Web Crypto API - MDN](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [SubtleCrypto.digest() - MDN](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest)
- [CryptoJS](https://cryptojs.gitbook.io/docs/)
- [Hash Functions Explained](https://en.wikipedia.org/wiki/Hash_function)
- [FileReader API - MDN](https://developer.mozilla.org/en-US/docs/Web/API/FileReader)
