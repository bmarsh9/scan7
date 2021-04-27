function notify_js(message,type="error") {
  $.notify({
      message: message
    },{
    type: type,
    animate: {
      enter: 'animated fadeInRight',
      exit: 'animated fadeOutRight'
    }
  });
}


