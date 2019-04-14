$(function () {   
	$('#saveEditRecord').click(function () { // событие при клике сохранения измененного url	      
	  if (productSave()) {
        $('#modalRecord').modal('hide');		
      }
   });	
});	

function EditProduct(id){ // обработчик: добавляет данные в модельное окно   
	$('#modalRecord .modal-title').text('Редактирование записи');
	$("#productId").val(id);	
	$("#mName").val($('#record'+id+' .Name').text());
	$("#mVersion").val($('#record'+id+' .Version').text());	
  $('#modalRecord').modal('show');
}

function AddProduct(){ // обработчик: добавляет данные в модельное окно      
	$('#modalRecord .modal-title').text('Добавление записи');
	$("#productId").val(0);	
	$("#mName").val('');
	$("#mVersion").val('');
	$('#modalRecord').modal('show');
}

function productSave(){
    if (($("#mName").val().length > 0)&&($("#mVersion").val().length > 0)) { 					
      var id = $("#productId").val();
      var request = $.ajax({							
        url: "/products/product/save",
        type: "POST",
        data: {id: id, name: $("#mName").val(), version: $("#mVersion").val()},
        dataType: "json",
        cache: false,
        timeout: 3000
      });
        
      request.done(function(msg) { // успешно	
        //alert('error.status='+msg.error.status);        
        if (msg.error.status) {
            if (id == 0) {       
              $("#contentProducts").append('<tr id="record'+msg.data.ID+'">'
                                    + '<td class="ID">'+msg.data.ID+'</td>'
                                    + '<td class="Name">'+$("#mName").val()+'</td>'
                                    + '<td class="Version">'+$("#mVersion").val()+'</td>'                                    
                                    + '<td class="KeyPrivate">'+msg.data.KeyPublicN+'</td>'
                                    + '<td class="KeyPublic">'+msg.data.KeyPublicE+'</td>'                                    
                                    + '<td>'
                                      + '<a class="cursor-pointer text-primary" onclick="EditProduct('+msg.data.ID+')"><span class="fa fa-edit"></span></a>'
                                      //+ '<a class="cursor-pointer text-primary" href="/products/product/'+msg.data.ID+'/delete"><span class="fa fa-trash"></span></a>'
                                    + '</td>'
                                  + '</tr>');                        
            } else {
                $('#record'+id+' .Name').text($("#mName").val());
                $('#record'+id+' .Version').text($("#mVersion").val());                
            }
            $('#modalRecord').modal('hide');
            return true
         } else { 										
            $("#message").empty().append('<div class="alert alert-danger otstup-vert10 text-center"><button type="button" class="close interval-right10" data-dismiss="alert" aria-hidden="true">&times;</button><strong>При сохранении произошла ошибка: '+msg.error.message+'</strong></div>');					
            return false;
        }				
      });
         
      request.fail(function(jqXHR, textStatus, errorThrown) { // не успешно								
        $("#message").empty().append('<div class="alert alert-danger otstup-vert10 text-center"><button type="button" class="close interval-right10" data-dismiss="alert" aria-hidden="true">&times;</button><strong>При сохранении произошла ошибка. Проверьте соединение с сервером.</strong></div>');					
        //alert( "ConnectError >> Request failed: " + textStatus+' - '+errorThrown );
        return false;				
      });		
    } else { 
      $("#message").empty().append('<div class="alert alert-warning otstup-vert10 text-center"><button type="button" class="close interval-right10" data-dismiss="alert" aria-hidden="true">&times;</button><strong>Заполните все реквизиты!</strong></div>');
      return false;
    }
  }