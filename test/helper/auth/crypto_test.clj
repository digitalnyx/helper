(ns helper.auth.crypto-test
  (:require 
   [clojure.test :refer :all]
   [helper.auth.crypto :refer :all]
   [helper.packet.utils :refer :all]))

;; key is the SRP s-key value.
;; Need to check if reversed on our (client) side.
(def s-key
  (reverse
   (big-num->bytes
    (BigInteger. 
     (str "05CF2D600777A492F6DAFC5DC7DCA2E1B091E744"
          "C3174D36DA7FDC44060F798E615B7F011C782348") 
     16))))

(def encrypted-server-header
  (seq->bytes [0x48 0x89 0x20 0x3E]))

(def server-header
  (seq->bytes [0x00 0x62 0xEF 0x02]))

(def encrypted-client-header
  (seq->bytes [0x48 0x6F 0xBE 0xDA 0xDB 0x5A]))

(def client-header
  (seq->bytes [0x00 0x04 0x37 0x00 0x00 0x00]))

(deftest byte-conversions

  (testing "Encryption"

    (is (java.util.Arrays/equals 
         ^bytes encrypted-server-header
         ^bytes (encrypt server-header s-key)))

    (is (java.util.Arrays/equals
         ^bytes encrypted-client-header
         ^bytes (encrypt client-header s-key))))

  (testing "Decryption"

    (is (java.util.Arrays/equals
         ^bytes server-header
         ^bytes (decrypt encrypted-server-header s-key)))
    
    (is (java.util.Arrays/equals
         ^bytes client-header
         ^bytes (decrypt encrypted-client-header s-key)))))
