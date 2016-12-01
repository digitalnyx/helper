(ns helper.auth.crypto
  (:require
   [helper.packet.utils :refer :all]))

;; key is the SRP s-key value.
(def test-key
  (reverse
   (big-num->bytes
    (BigInteger. "05CF2D600777A492F6DAFC5DC7DCA2E1B091E744C3174D36DA7FDC44060F798E615B7F011C782348" 16))))

(def test-val
  (seq->bytes [0x48 0x89 0x20 0x3E]))

(def test-val-1
  (seq->bytes [0x00 0x62 0xEF 0x02]))

(def test-val$
  (seq->bytes [0x48 0x6F 0xBE 0xDA 0xDB 0x5A]))

(defn byte->ubyte
  [x]
  (format "0x%02X" 
          (bit-and 0xFF (Short. (short x)))))

(defn encrypt
  [val key]
  (let [val-len (count val)
        key-len (count key)
        encrypted (byte-array val-len)]
    (with-local-vars
        [send-i 0
         send-j 0]
      (doseq [i (range val-len)]
        (var-set send-i (mod @send-i key-len))
        (aset-byte encrypted i
                   (unchecked-byte
                    (+ (bit-xor 
                        (nth val i )
                        (nth key @send-i))
                       @send-j)))
        (var-set send-i (inc @send-i))
        (var-set send-j (nth encrypted i))))
    encrypted))

(defn decrypt
  [val key]
  (let [val-len (count val)
        key-len (count key)
        decrypted (byte-array val-len)]
   (with-local-vars 
       [recv-i 0 
        recv-j 0]
     (doseq [i (range val-len)]
       (var-set recv-i (mod @recv-i key-len))
       (aset-byte decrypted i
                 (unchecked-byte 
                  (bit-xor
                   (- (nth val i) @recv-j)
                   (nth key @recv-i))))
       (var-set recv-i (inc @recv-i))
       (var-set recv-j (nth val i 0))))
   decrypted))

;; Winner
;; (decrypt test-val (reverse test-key))
;; (map byte->ubyte *1)
