'use strict'

var stream = require('stream')
var net = require('chrome-net')

/*

this is not working yet. _transform is one to one, which means i need
to segment the tls packets and be aware of the payload lengths, to know when
a transform is complete

*/

class TLSContext {
  constructor() {
    // using a worker thread would be better. shrug
    this._encryptQueue = []
    this._decryptQueue = []
  }
  verify(connection, verified, depth, certs) {
    return true
  }
  _do_decrypt() {
    var self = this
    if (! this._decrypt_callback && this._decryptQueue.length > 0) {
      console.log('do decrypt')
      var [data,cb] = this._decryptQueue.shift()
      this._decrypt_callback = function(err, dec) {
        console.log('data was decrypted', dec.length, data.length)
        cb(err, dec)
        //self._do_decrypt()
      }
      var b = data.toString('binary')
      console.log('forge process (decrypt)',data.length)
      self.forgesocket.process(b)
    }
  }
  _do_encrypt() {
    var self = this
    if (! this._encrypt_callback && this._encryptQueue.length > 0) {
      console.log('do encrypt')
      var [data,cb] = this._encryptQueue.shift()
      this._encrypt_callback = function(err, enc) {
        console.log('data was encrypted', enc.length, data.length)
        cb(err, enc)
        //self._do_encrypt()
      }
      var b = data.toString('binary')
      console.log('forge prepare (encrypt)',data.length)
      self.forgesocket.prepare(b)
    }
  }
  decrypt_data(data, callback) {
    //console.log('decrypt data',data)
    this._decryptQueue.push([data,callback])
    this._do_decrypt()
  }
  encrypt_data(data, callback) {
    //console.log('encrypt data',data)
    this._encryptQueue.push([data,callback])
    this._do_encrypt()
  }
  establish(options, callback) {
    var port = options.port
    var host = options.host
    var connect_callback = callback
    var self = this
    var tls_established = false
    
    this.rawsocket = new net.Socket();

    var client = forge.tls.createConnection({
      server: false,
      verify: this.verify,
      connected: function(connection) {
        console.log('%c [tls] connected','background: #0f0; color: #0ae');
        tls_established = true
        if (connect_callback) { connect_callback() }
      },
      tlsDataReady: function(connection) {
        var bytes = connection.tlsData.getBytes();
        if (tls_established) {
          console.log('(->send)tlsDataReady',bytes)
          var buf = Buffer.from(bytes,'binary')
          self._encrypt_callback(null, buf)
          self._encrypt_callback = null
          self._do_encrypt()
          //self.push(data) // pipes to raw socket
          // self.rawsocket.write(data, 'binary')
        } else {
          console.log('rawsocket write')
          self.rawsocket.write(bytes, 'binary')
        }
      },
      dataReady: function(connection) {
        // XXX this can get called twice for a single input (!!!)

        // XXX: bytes 3-4 give record length (excluding header)
        
        console.log('data ready')
        var bytes = connection.data.getBytes()
        if (tls_established) {
          console.log('(<-recv)dataReady')
          var buf = Buffer.from(bytes, 'binary')
          self._decrypt_callback(null, buf)
          self._decrypt_callback = null
          self._do_decrypt()
        } else {
          self.forgesocket.process(bytes); // calls dataReady
        }
      },
      closed: function() {
        console.log('[tls] disconnected')
      },
      error: function(connection, error) {
        console.log('[tls] error', error);
      }
    })

    this.forgesocket = client
    this.rawsocket.on('error', function(e) {
      console.error('rawsocket error') // connection closed perhaps.
    })
    this.rawsocket.on('connect', function() {
      console.log('[socket] connected');
      self.forgesocket.handshake();
    });
    /*
    this.rawsocket.on('readable', function() {
      console.log('rawsocket readable')
    })*/
    this.rawsocket.on('data', function(data) {
      //console.log('rawsocket data')
      if (! tls_established) {
        var b = data.toString('binary')
        self.forgesocket.process(b)
      } else {
        // should unattach this listener
      }
    })
    this.rawsocket.connect(port, host);
  }
}

class MyTransform extends stream.Transform {
  constructor(context, type) {
    super()
    this.context = context
    this.type = type
  }
  _transform(chunk, encoding, callback) {
    // calls either encrypt_data or decrypt_data
    console.log('transform',this.type)
    var method = this.context[this.type + '_data']
    return method.call(this.context, chunk, callback)
  }
}

class TLSSocket extends stream.Duplex {
  constructor(options, connect_callback) {
    super();
    var self = this
    this.encrypted = true
    this.readable = false

    this.context = new TLSContext
    this.context.establish(options, function(sock) {
      self._readTransform = new MyTransform(self.context, 'decrypt') // readable
      self._writeTransform = new MyTransform(self.context, 'encrypt') // writeable

      // readable raw socket -> decrypt -> self
      self.context.rawsocket
        .pipe( self._readTransform )

      // self -> encrypt -> writable raw socket
      self._writeTransform
        .pipe( self.context.rawsocket )

      self.emit('connect')
      //self._try_read(4096)
      if (connect_callback) { connect_callback() }
    })
  }
  _try_read(size) {
    console.log('_try_read')
    this.context.rawsocket.read(size)
  }
  _read(size) {
    if (this._readTransform)
      this._try_read(size)
  }
  _write(chunk, encoding, callback) {
    console.log('tls socket write',chunk)
    this._writeTransform.write(chunk, encoding, callback)
  }
}


exports.connect = function(options, callback) {
  return new TLSSocket(options, callback)
}
