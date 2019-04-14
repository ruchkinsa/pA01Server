$(function () {   
	$('#saveEditRecord').click(function () { // событие при клике сохранения измененного url	      
	  if (keySave()) {
        $('#modalRecord').modal('hide');		
    }         
   });	

   getTableStatus();
   getTableTypes();
   getTableProducts();       
   $('#mProduct').parent().addClass('hide');
});	

function EditKey(id){ // обработчик: добавляет данные в модельное окно   
  $('#modalRecord .modal-title').text('Редактирование записи');
  $('#mProduct').parent().addClass('hide');
	$("#keyId").val(id);		
  $("#mExpirationDate").val($('#record'+id+' .ExpirationDate').text()); 	
  $("#mType option").removeClass('color-orange').removeAttr("selected");     
  $("#mType option:contains("+$('#record'+id+' .Type').text()+")").addClass('color-orange').prop('selected',true);
  $("#mStatus option").removeClass('color-orange').removeAttr("selected");     
  $("#mStatus option:contains("+$('#record'+id+' .Status').text()+")").addClass('color-orange').prop('selected',true);
  $('#modalRecord').modal('show');
}

function AddKey(){ // обработчик: добавляет данные в модельное окно      
	$('#modalRecord .modal-title').text('Добавление записи');
	$("#keyId").val(0);		
  $("#mExpirationDate").val('');  
	$("#mType option").removeClass('color-orange').removeAttr("selected");  
  $("#mType").find("[value = 1]").addClass('color-orange').prop('selected',true);
  $("#mStatus option").removeClass('color-orange').removeAttr("selected");  
  $("#mStatus").find("[value = 1]").addClass('color-orange').prop('selected',true);
  $('#mProduct').parent().removeClass('hide');


  $('#modalRecord').modal('show');  
}

function keySave(){  
    if (($("#mExpirationDate").val().length > 0)&&($("#mStatus").val().length > 0)&&($("#mType").val().length > 0)&&($("#mProduct").val().length > 0)) { 					
        var id = $("#keyId").val();
        //alert("id="+id);
        var request = $.ajax({							
          url: "/keys/key/save",
          type: "POST",
          data: {id: id, expirationDate: $("#mExpirationDate").val(), status: $("#mStatus").val(), type: $("#mType").val(), product: $("#mProduct").val()},
          dataType: "json",
          cache: false,
          timeout: 3000
        });
          
        request.done(function(msg) { // успешно	
          //alert('status='+ msg.error.status);          
          if (msg.error.status) {             
              if (id == 0) {                  
                 $("#contentKeys").append('<tr id="record'+msg.data.ID+'">'
                                    + '<td class="ID">'+msg.data.ID+'</td>'
                                    + '<td class="KeyText">'+msg.data.KeyText+'</td>'
                                    + '<td class="Status">'+$("#mType option:selected").text()+'</td>'
                                    + '<td class="ExpirationDate">'+msg.data.ExpirationDate+'</td>'
                                    + '<td class="LastUsed">'+msg.data.LastUsed+'</td>'
                                    + '<td class="Status">'+$("#mStatus option:selected").text()+'</td>'
                                    + '<td class="KeyPrivate">'+msg.data.KeyPublicN+'</td>'
                                    + '<td class="KeyPublic">'+msg.data.KeyPublicE+'</td>'
                                    + '<td class="Product">'+$("#mProduct option:selected").text()+'</td>'
                                    + '<td>'
                                      + '<a class="cursor-pointer text-primary" onclick="EditKey('+msg.data.ID+')"><span class="fa fa-edit"></span></a>'
                                      + '<a class="cursor-pointer text-primary" href="/keys/key/'+msg.data.ID+'/delete"><span class="fa fa-trash"></span></a>'
                                    + '</td>'
                                  + '</tr>');                
              } else {                  
                  $('#record'+id+' .Type').text($("#mType option:selected").text());
                  $('#record'+id+' .ExpirationDate').text($("#mExpirationDate").val());
                  $('#record'+id+' .Status').text($("#mStatus option:selected").text());                  
              }
              $('#modalRecord').modal('hide');
              return true;
           } else {                            
              $("#message").empty().append('<div class="alert alert-danger otstup-vert10 text-center"><button type="button" class="close interval-right10" data-dismiss="alert" aria-hidden="true">&times;</button><strong>При сохранении произошла ошибка: '+msg.error.message+'</strong></div>');					
              return false;
          }				
        });
           
        request.fail(function(jqXHR, textStatus, errorThrown) { // не успешно								
          $("#message").empty().append('<div class="alert alert-danger otstup-vert10 text-center"><button type="button" class="close interval-right10" data-dismiss="alert" aria-hidden="true">&times;</button><strong>При сохранении произошла ошибка:'+textStatus+' - '+errorThrown+'. Проверьте соединение с сервером.</strong></div>');					
          //alert( "ConnectError >> Request failed: " + textStatus+' - '+errorThrown );
          return false;				
        });		
      } else { 
        $("#message").empty().append('<div class="alert alert-warning otstup-vert10 text-center"><button type="button" class="close interval-right10" data-dismiss="alert" aria-hidden="true">&times;</button><strong>Заполните все реквизиты!</strong></div>');
        return false;
    }
  }

  function getTableStatus(){          
        var request = $.ajax({							
          url: "/db/getTStatus",
          type: "GET",          
          dataType: "json",
          cache: false,
          timeout: 3000
        });          
        request.done(function(msg) { // успешно	
          //alert('status='+ msg.error.status);          
          if (msg.error.status) {    
            var content = '';
            $.each(msg.data, function(id, rec){
              //alert(id + ' => '+ name);
              content += '<option class="" value="'+rec.ID+'">'+rec.Name+'</option>';					   
            });
            $("#mStatus").empty().append(content);
            return true
           } else {                           
              $("#message").empty().append('<div class="alert alert-danger otstup-vert10 text-center"><button type="button" class="close interval-right10" data-dismiss="alert" aria-hidden="true">&times;</button><strong>При запросе данных произошла ошибка: '+msg.error.message+'</strong></div>');					
              return false;
          }				
        });           
        request.fail(function(jqXHR, textStatus, errorThrown) { // не успешно								
          $("#message").empty().append('<div class="alert alert-danger otstup-vert10 text-center"><button type="button" class="close interval-right10" data-dismiss="alert" aria-hidden="true">&times;</button><strong>При запросе данных произошла ошибка:'+textStatus+' - '+errorThrown+'. Проверьте соединение с сервером.</strong></div>');					
          //alert( "ConnectError >> Request failed: " + textStatus+' - '+errorThrown );
          return false;				
        });		      
  }

  function getTableTypes(){          
    var request = $.ajax({							
      url: "/db/getTTypes",
      type: "GET",          
      dataType: "json",
      cache: false,
      timeout: 3000
    });          
    request.done(function(msg) { // успешно	
      //alert('status='+ msg.error.status);          
      if (msg.error.status) {    
        var content = '';
        $.each(msg.data, function(id, rec){
          //alert(id + ' => '+ name);
          content += '<option class="" value="'+rec.ID+'">'+rec.Name+'</option>';					   
        });
        $("#mType").empty().append(content);
        return true
       } else {                           
          $("#message").empty().append('<div class="alert alert-danger otstup-vert10 text-center"><button type="button" class="close interval-right10" data-dismiss="alert" aria-hidden="true">&times;</button><strong>При запросе данных произошла ошибка: '+msg.error.message+'</strong></div>');					
          return false;
      }				
    });           
    request.fail(function(jqXHR, textStatus, errorThrown) { // не успешно								
      $("#message").empty().append('<div class="alert alert-danger otstup-vert10 text-center"><button type="button" class="close interval-right10" data-dismiss="alert" aria-hidden="true">&times;</button><strong>При запросе данных произошла ошибка:'+textStatus+' - '+errorThrown+'. Проверьте соединение с сервером.</strong></div>');					
      //alert( "ConnectError >> Request failed: " + textStatus+' - '+errorThrown );
      return false;				
    });		      
}

  function getTableProducts(){          
    var request = $.ajax({							
      url: "/db/getTProducts",
      type: "GET",          
      dataType: "json",
      cache: false,
      timeout: 3000
    });          
    request.done(function(msg) { // успешно	
      //alert('status='+ msg.error.status);          
      if (msg.error.status) {    
        var content = '';
        //alert('data='+msg.data);        
        if ((msg.data) && (msg.data.length > 0)) {
          $.each(msg.data, function(id, rec){ content += '<option class="" value="'+rec.ID+'">'+rec.Name+'</option>'; });          
          $("#mProduct").empty().append(content); 
          return true;
        } else { 
            $("#mProduct").empty(); 
            $("#message").empty().append('<div class="alert alert-danger otstup-vert10 text-center"><button type="button" class="close interval-right10" data-dismiss="alert" aria-hidden="true">&times;</button><strong>При запросе данных произошла ошибка: '+msg.error.message+'</strong></div>');					
            return false;
        }        
        alert('!');        
       } else {
          $("#mProduct").empty();
          $("#message").empty().append('<div class="alert alert-danger otstup-vert10 text-center"><button type="button" class="close interval-right10" data-dismiss="alert" aria-hidden="true">&times;</button><strong>При запросе данных произошла ошибка: '+msg.error.message+'</strong></div>');					
          return false;
      }				
    });           
    request.fail(function(jqXHR, textStatus, errorThrown) { // не успешно								
      $("#message").empty().append('<div class="alert alert-danger otstup-vert10 text-center"><button type="button" class="close interval-right10" data-dismiss="alert" aria-hidden="true">&times;</button><strong>При запросе данных произошла ошибка:'+textStatus+' - '+errorThrown+'. Проверьте соединение с сервером.</strong></div>');					
      //alert( "ConnectError >> Request failed: " + textStatus+' - '+errorThrown );
      return false;				
    });		      
  }
  