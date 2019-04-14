function checkKey() {    
    $('#log').empty().append('<hr><p>Запрос проверки ключа ...</p>');
    var request = $.ajax({							
        url: "/testing/license/check",
        type: "POST",          
        dataType: "json",
        data: { keyText: $("#keyText").val(), keyPublicN: $("#keyPublicN").val(), keyPublicE: $("#keyPublicE").val() },
        cache: false,
        timeout: 3000
      });          
      request.done(function(msg) { // успешно	         
        //alert('msg.status = '+msg.status);             
        if (msg.status) {
            $('#log').append('<p>Результат: лицензия подтверждена</p>');
            return true
         } else {  
            $('#log').append('<p>При запросе данных произошла ошибка: '+msg.message+'</p>');            
            return false;
        }				
      });           
      request.fail(function(jqXHR, textStatus, errorThrown) { // не успешно								
        $('#log').append('<p>При запросе данных произошла ошибка: '+textStatus+' - '+errorThrown+'. Проверьте соединение с сервером.</p>');					
        //alert( "ConnectError >> Request failed: " + textStatus+' - '+errorThrown );
        return false;				
      });		
}

function activateKey() {    
    $('#log').empty().append('<hr><p>Запрос активации ключа ...</p>');
    var request = $.ajax({							
        url: "/testing/license/activate",
        type: "POST",          
        dataType: "json",
        data: { keyPublicN: $("#keyPublicN").val(), keyPublicE: $("#keyPublicE").val() },
        cache: false,
        timeout: 3000
      });          
      request.done(function(msg) { // успешно	      
        if (msg.error.status) {    
            $('#log').append('<p>Key: <span id="cryptoKey">'+msg.key+'</span></p>');
            $('#log').append('<p>Signature: <span id="cryptoSignature">'+msg.signature+'</span></p>');            
            $('#log').append('<p><button id="checkCrypto" type="button" class="btn btn-info btn-sm" onclick="checkCrypto()">Check Crypto</button></p>');
            return true
         } else {  
            $('#log').append('<p>При запросе данных произошла ошибка: '+msg.error.message+'</p>');            
            return false;
        }				
      });           
      request.fail(function(jqXHR, textStatus, errorThrown) { // не успешно								
        $('#log').append('<p>При запросе данных произошла ошибка: '+textStatus+' - '+errorThrown+'. Проверьте соединение с сервером.</p>');					
        //alert( "ConnectError >> Request failed: " + textStatus+' - '+errorThrown );
        return false;				
      });
}

function checkCrypto () {
  alert('checkCrypto');

}