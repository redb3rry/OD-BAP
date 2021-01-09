document.addEventListener('DOMContentLoaded', function (event) {

    var HTTP_STATUS = {OK: 200, CREATED: 201, NOT_FOUND: 404};

    let fileForm = document.getElementById("file-form");
    fileForm.addEventListener("submit", function (event) {
        event.preventDefault();

        let file = document.getElementById("file")
        let input = document.querySelector('input[type="file"]')
        let data = new FormData()
        data.append('file', input.files[0])

        if (isRightExtension(file) === false) {
            return alert("Only .txt .png .jpg and .jpeg files are accepted.")
        } else {
            uploadFile(data)
        }
    });

    function isRightExtension(file) {
        let extension = file.files[0].name.split('.').pop();
        console.log(extension)
        return extension === "png" || extension === "jpg" || extension === "jpeg" || extension === "txt";
    }

    function uploadFile(file) {
        let url = "https://localhost/upload-file"
        let csrf_token = document.getElementById('csrf_token').value
        let params = {
            method: 'POST',
            body: file,
            redirect: "follow",
            credentials: 'include',
            mode: 'cors',
            headers:{
                'X-CSRFToken':csrf_token
            }
        }
        fetch(url, params).then(function (resp) {
            console.log("Response: " + resp.status);
            if (resp.status === HTTP_STATUS.OK || resp.status === HTTP_STATUS.CREATED) {
                window.location.href = "/filelist";
                return resp.json();
            } else {
                console.error("Response status code: " + resp.status);
                throw "Unexpected response status: " + resp.status;
            }

        }).catch(function (err) {
            console.log("Error: " + err);
            return err.status;
        })
    }

});