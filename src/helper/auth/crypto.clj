(ns helper.auth.crypto
  (:require
   [helper.utils.conversions :refer :all]))

(defn build-head-encrypter
  [key]
  (let [key-len (count key)
        send-i (atom 0)
        send-j (atom 0)]
    (fn [col len]
      (let [[to-encrypt rest] (split-at len col)
            encrypted (byte-array len)]
        (doseq [i (range len)]
          (reset! send-i (mod @send-i key-len))
          (aset-byte encrypted i
                     (unchecked-byte
                      (+ (bit-xor 
                          (nth col i)
                          (nth key @send-i))
                         @send-j)))
          (reset! send-i (inc @send-i))
          (reset! send-j (nth encrypted i)))
        (concat encrypted rest)))))

(defn build-head-decrypter
  [key]
  (let [key-len (count key)
        recv-i (atom 0)
        recv-j (atom 0)]
    (fn [col len]
      (let [[to-decrypt rest] (split-at len col)
            decrypted (byte-array len)]
        (doseq [i (range len)]
          (reset! recv-i (mod @recv-i key-len))
          (aset-byte decrypted i
                     (unchecked-byte 
                      (bit-xor
                       (- (nth col i) @recv-j)
                       (nth key @recv-i))))
          (reset! recv-i (inc @recv-i))
          (reset! recv-j (nth col i 0)))
        (concat decrypted rest)))))

