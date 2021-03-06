// отправляет запрос генератору ключей
async function key_RSA() {
    let forlder = document.getElementById("input-box").value;

    let key_gen = await eel.generateRSA(forlder)();
    document.getElementById("info_rsa").innerHTML = key_gen;
    console.log(key_gen)
}

jQuery("#generate").on('click', function() {
    key_RSA();
});

// отправляет запрос шифратуру 
async function crypt_file() {
    let forlder_crypt = document.getElementById("crypt_dir").value;
    let public_key = document.getElementById("crypt_file").value;
    console.log(public_key);
    console.log(forlder_crypt);
    
    let start_crypt = await eel.walk(forlder_crypt, public_key)();
    document.getElementById("dis_crypt").innerHTML = start_crypt;
    console.log(start_crypt);
}

jQuery("#crypt_start").on('click', function() {
    crypt_file();
});

// отправляет запрос дешифратуру
async function decrypt_file() {
    let forlder_decrypt = document.getElementById("decrypt_dir").value;
    let private_key = document.getElementById("decrypt_file").value;
    console.log(private_key);
    console.log(forlder_decrypt);

    let start_decrypt = await eel.walk_decrypt(forlder_decrypt, private_key)();
    document.getElementById("dis_decrypt").innerHTML = start_decrypt;
    console.log(start_decrypt)
}

jQuery("#decrypt_start").on("click", function(){
    decrypt_file()
});

// очиска результатов
async function clear() {
    await eel.clear_results()
}

jQuery("#clear_results").on('click', function() {
    clear()
});