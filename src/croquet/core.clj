(ns croquet.core
  (:require [clojure.core.async :as ca]
            [clojure.java.io :as jio])
  (:import [java.nio ByteBuffer]
           [java.security KeyStore]
           [java.util Properties]
           [javax.net.ssl TrustManagerFactory KeyManagerFactory SSLContext]
           [org.bouncycastle.cert.jcajce JcaX509CertificateConverter]
           [org.bouncycastle.openssl PEMParser PEMEncryptedKeyPair]
           [org.bouncycastle.openssl.jcajce JcePEMDecryptorProviderBuilder JcaPEMKeyConverter]
           [org.eclipse.paho.client.mqttv3 IMqttAsyncClient MqttAsyncClient TimerPingSender IMqttActionListener IMqttToken MqttMessage IMqttMessageListener MqttConnectOptions]
           [org.eclipse.paho.client.mqttv3.persist MqttDefaultFilePersistence]))

(defn success?
  [^IMqttToken token]
  (and (.isComplete token) (nil? (.getException token))))

(defn exception
  [^IMqttToken token]
  (.getException token))

(defn granted-qos
  [^IMqttToken token]
  (.getGrantedQos token))

(defn message-id
  [^IMqttToken token]
  (.getMessageId token))

(defn qos
  [^MqttMessage msg]
  (.getQos msg))

(defn payload
  [^MqttMessage msg]
  (.getPayload msg))

(defn client
  "Create a new async MQTT client."
  [uri client-id & {:keys [persistence ping-sender]}]
  (MqttAsyncClient. uri client-id
                    (or persistence (MqttDefaultFilePersistence.))
                    (or ping-sender (TimerPingSender.))))

(defn- action-callback
  [channel]
  (reify IMqttActionListener
    (onFailure [_ token _] (ca/put! channel token))
    (onSuccess [_ token] (ca/put! channel token))))

(defn- ssl-socket-factory
  [ca-file cert-file key-file key-password]
  (let [ca-cert (when ca-file
                  (with-open [reader (PEMParser. (jio/reader ca-file))]
                    (.getCertificate (JcaX509CertificateConverter.)
                                     (.readObject reader))))
        cert (when cert-file
               (with-open [reader (PEMParser. (jio/reader cert-file))]
                 (.getCertificate (JcaX509CertificateConverter.)
                                  (.readObject reader))))
        key (when cert-file
              (with-open [parser (PEMParser. (jio/reader key-file))]
                (let [k (.readObject parser)]
                  (if (instance? PEMEncryptedKeyPair k)
                    (.decryptKeyPair k (.build (JcePEMDecryptorProviderBuilder.) key-password))
                    k))))
        tmp-password (.toCharArray (name (gensym "croquet.")))
        trust-manager (when ca-cert
                        (doto (TrustManagerFactory/getInstance (TrustManagerFactory/getDefaultAlgorithm))
                          (.init (doto (KeyStore/getInstance (KeyStore/getDefaultType))
                                   (.load nil nil)
                                   (.setCertificateEntry "ca-certificate" ca-cert)))))
        key-manager (when (and cert key)
                      (doto (KeyManagerFactory/getInstance (KeyManagerFactory/getDefaultAlgorithm))
                        (.init
                          (doto (KeyStore/getInstance (KeyStore/getDefaultType))
                            (.load nil nil)
                            (.setCertificateEntry "certificate" cert)
                            (.setKeyEntry "key" (.getPrivateKey (JcaPEMKeyConverter.)
                                                                (.getPrivateKeyInfo key)) tmp-password (into-array [cert])))
                          tmp-password)))
        context (doto (SSLContext/getInstance "TLS")
                  (.init (when key-manager (.getKeyManagers key-manager))
                         (when trust-manager (.getTrustManagers trust-manager))
                         nil))]
    (.getSocketFactory context)))

(defn- mk-options
  "Turn an option map into a MqttConnectOptions object."
  [m]
  (let [{:keys [timeout
                keep-alive
                ca-file
                cert-file
                key-file
                key-password
                password
                ssl-properties]} m
        opts (MqttConnectOptions.)]
    (when timeout (.setConnectionTimeout opts timeout))
    (when keep-alive (.setKeepAliveInterval opts keep-alive))
    (when (or ca-file cert-file key-file)
      (.setSocketFactory opts (ssl-socket-factory ca-file cert-file key-file key-password)))
    (when password (.setPassword opts password))
    (when ssl-properties (.setSSLProperties opts (Properties. ssl-properties)))
    opts))

(defn connect
  "Connects a client to the remote server."
  [^IMqttAsyncClient client opts]
  (let [ch (ca/chan)]
    (.connect client (mk-options opts) nil (action-callback ch))
    ch))

(defn disconnect
  [^IMqttAsyncClient client & {:keys [force? quiesce-ms disconnect-ms] :or {quiesce-ms 30000 disconnect-ms 30000}}]
  (if force?
    (ca/thread
      (.disconnectForcibly client quiesce-ms disconnect-ms))
    (let [ch (ca/chan)]
      (.disconnect client quiesce-ms nil (action-callback ch))
      ch)))

(defn- as-byte-array
  [val]
  (cond
    (bytes? val) val
    (instance? ByteBuffer val) (let [buf (.duplicate val)
                                     b (byte-array (.remaining buf))]
                                 (.get buf b)
                                 b)
    :else (throw (IllegalArgumentException. "don't know how to convert payload"))))

(defn ^MqttMessage mqtt-message
  "Attempt to coerce val to an MQTT message."
  [val]
  (cond
    (instance? MqttMessage val) val
    (map? val) (let [{:keys [payload qos retained?]} val]
                 (doto (MqttMessage. (as-byte-array payload))
                   (.setQos (or qos 0))
                   (.setRetained (or retained? false))))
    :else (MqttMessage. (as-byte-array val))))

(defn publish
  "Publishes a message. Returns a channel that returns a token when
   the publish completes or fails."
  [^IMqttAsyncClient client ^String topic message]
  (let [ch (ca/chan)
        msg (mqtt-message message)]
    (.publish client topic msg nil (action-callback ch))
    ch))

(defn subscribe
  "Subscribes to a topic. Returns a channel that produces tuples
   of [topic, message] when messages arrive."
  [^IMqttAsyncClient client ^String topic & {:keys [qos] :or {qos 0}}]
  (let [ch (ca/chan)
        action-cb (reify IMqttActionListener
                    (onFailure [_ _ _]
                      (ca/close! ch))
                    (onSuccess [_ _]))
        msg-cb (reify IMqttMessageListener
                 (messageArrived [_ topic message]
                   (ca/put! ch [topic message])))]
    (.subscribe client topic qos nil action-cb msg-cb)
    ch))

(defn unsubscribe
  [^IMqttAsyncClient client ^String topic]
  (let [ch (ca/chan)]
    (.unsubscribe client topic nil (action-callback ch))
    ch))
