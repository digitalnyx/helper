(ns helper.utils.shine
  (:require
   [helper.utils.conversions :as conv]
   [gloss.core :as gloss]
   [gloss.io :as io])
  (:use
   [gloss.data bytes string primitives]
   [gloss.core protocols structure formats]))

(def black-hole
  (reify
    gloss.core.protocols/Reader
    (read-bytes [_ b]
      (comment (println "Reading from Black Hole."))
      [true nil nil])
    gloss.core.protocols/Writer
    (sizeof [_]
      nil)
    ;; v is the map, or whatever is being written.
    ;; buf is a java.nio.HeapByteBuffer
    ;; nil is returned is sizeof returns nil!
    (write-bytes [_ buf v]
      (comment
       (println "Writing to Black Hole.")
       (println buf)
       (println v))
      )))

(defn header+ [codec header->body body->header]
  (let [read-codec (compose-callback
		     codec
		     (fn [v b]
		       (let [body (header->body v)]
			 (read-bytes body b))))]
    (reify
      Reader
      (read-bytes [_ buf-seq]
	(read-bytes read-codec buf-seq))
      Writer
      (sizeof [_]
	nil)
      (write-bytes [_ buf val]
	(when-let [header (body->header val)]
           (when-let [body (header->body header)]
             (if (and (sizeof codec) (sizeof body))
               (with-buffer [buf (+ (sizeof codec) (sizeof body))]
                 (write-bytes codec buf header)
                 (write-bytes body buf val))
               (concat
                (write-bytes codec buf header)
                (write-bytes body buf val)))))
        ))))


(defn unk
  [frame val & {:keys [key]}]
  (gloss/compile-frame
   frame 
   (fn [v] 
     (if (and key (get v key)) 
       (get v key)
       val))
   (fn [v] v)))

(defn bignum
  [& {:keys [length prefix reverse?] 
      :or {length 0 prefix :none reverse? false}}]
  (let [enc-fn (if reverse?
                 #(reverse (conv/big-num->bytes %))
                 #(conv/big-num->bytes %))
        dec-fn (if reverse? 
                 #(conv/bytes->big-num (reverse %))
                 #(conv/bytes->big-num %))
        frame (if (= prefix :none)
                (gloss/finite-frame 
                 length
                 (gloss/repeated :ubyte :prefix :none))
                (gloss/repeated 
                 :ubyte
                 :prefix (gloss/prefix prefix)))]
    (gloss/compile-frame
     frame enc-fn dec-fn)))

(defn openssl-bignum
  [& {:keys [length prefix reverse] 
      :or {length 0 prefix :none reverse false}}]
  (bignum :length length
          :prefix prefix
          :reverse? true))

