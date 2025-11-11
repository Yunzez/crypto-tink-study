ui = true
disable_mlock = true

listener "tcp" {
  address       = "127.0.0.1:8200"
  tls_disable   = 0
  tls_cert_file = "/Users/yunzezhao/Code/crypto-tink-study/tink-demo/127.0.0.1+1.pem"
  tls_key_file  = "/Users/yunzezhao/Code/crypto-tink-study/tink-demo/127.0.0.1+1-key.pem"
}

storage "inmem" {}

api_addr     = "https://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"
