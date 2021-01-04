document.addEventListener('DOMContentLoaded', function (event) {

    let passwordInput = document.getElementById("reg-password")
    passwordInput.addEventListener("change", updatePasswordStrength);

    function updatePasswordStrength() {
        let password = passwordInput.value
        console.log(password)
        let strengthBar = document.getElementById("password-strength")
        let passwordEntropy = countEntropy(password)
        console.log("Entropy: "+passwordEntropy)
        if (passwordEntropy < 3) {
            console.log("weak")
            strengthBar.setAttribute("class", "progress-bar w-25 bg-danger")
        } else if (passwordEntropy < 4) {
            console.log("ok")
            strengthBar.setAttribute("class", "progress-bar w-50 bg-warning")
        } else if (passwordEntropy < 5) {
            console.log("good")
            strengthBar.setAttribute("class", "progress-bar w-75 bg-info")
        } else {
            console.log("great")
            strengthBar.setAttribute("class", "progress-bar w-100 bg-success")
        }

    }

    function countEntropy(password) {
        const set = {};

        password.split('').forEach(
            c => (set[c] ? set[c]++ : (set[c] = 1))
        );

        return Object.keys(set).reduce((H, c) => {
            const p = set[c] / password.length;
            return H - (p * (Math.log(p) / Math.log(2)));
        }, 0);
    }
});