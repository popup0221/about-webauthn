# Registration(등록)

## **API**



### **등록**

`PublicKeyCredentialCreationOptions` 구성 요소

이 API에서 클라이언트에게 전달할 `PublicKeyCredentialCreationOptions` 객체는 다음과 같은 필수 요소들을 포함합니다:

* **challenge**: 등록 요청의 고유성을 보장하는 임의의 데이터(서버에서 생성).
* **rp**: 등록 요청을 생성하는 Relying Party(즉, 서버)의 정보.
* **user**: 등록할 사용자의 정보(서버에서 생성).
* **pubKeyCredParams**: 사용자가 생성할 공개 키의 유형과 알고리즘.
* **authenticatorSelection**: 인증기(Authenticator)의 유형 및 요구 사항(옵션).
* **timeout**: 클라이언트가 등록을 완료하는 데 주어지는 시간(옵션).
* **attestation**: attestation 방식 (none, direct, indirect 등).

2. **Java로 구현된 예시 코드**

```java
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.RpEntity;
import com.webauthn4j.data.UserEntity;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.AuthenticatorSelectionCriteria;
import com.webauthn4j.data.attestation.AttestationConveyancePreference;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;
import java.util.Collections;

@RestController
public class WebAuthnController {

    @PostMapping("/webauthn/register/options")
    public ResponseEntity<PublicKeyCredentialCreationOptions> getRegistrationOptions(@RequestBody RegistrationRequest request) {
        // 1. 서버에서 고유한 챌린지 생성
        Challenge challenge = new DefaultChallenge();

        // 2. RP 정보 설정
        RpEntity rpEntity = new RpEntity("example.com", "Example");

        // 3. 사용자 정보 설정
        // 사용자 ID, 이름 등. 사용자 ID는 고유해야 함
        UserEntity userEntity = new UserEntity(request.getUserId(), request.getUsername(), request.getDisplayName());

        // 4. PublicKeyCredentialParameters 설정 (지원할 공개 키 알고리즘)
        PublicKeyCredentialParameters publicKeyCredParams = new PublicKeyCredentialParameters(
            "public-key", // PublicKeyCredentialType
            -7 // ES256 (ECDSA with SHA-256)
        );

        // 5. AuthenticatorSelectionCriteria 설정 (인증기 요구 사항)
        AuthenticatorSelectionCriteria authenticatorSelection = new AuthenticatorSelectionCriteria();
        authenticatorSelection.setUserVerificationRequirement("preferred");

        // 6. PublicKeyCredentialCreationOptions 생성
        PublicKeyCredentialCreationOptions options = new PublicKeyCredentialCreationOptions(
            rpEntity,
            userEntity,
            challenge,
            Collections.singletonList(publicKeyCredParams),
            authenticatorSelection,
            null, // ExcludeCredentials - 기존 자격 증명을 배제할지 여부
            null, // AuthenticationExtensionsClientInputs - 클라이언트 확장 (옵션)
            60000L, // Timeout 설정 (1분)
            AttestationConveyancePreference.NONE // Attestation 방식
        );

        // 7. 생성된 옵션을 클라이언트에게 반환
        return ResponseEntity.ok(options);
    }
}

```
