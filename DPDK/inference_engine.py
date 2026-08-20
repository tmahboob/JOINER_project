import numpy as np
import tensorflow as tf
import time
import os

class StreamingInferenceEngine:

    def __init__(self,
                 file_path="/tmp/dpdk_modbus_features.bin",
                 batch_size=12,
                 feature_size=27):

        self.file_path = file_path
        self.batch_size = batch_size
        self.feature_size = feature_size

        print("⏳ Loading model...")
        self.model = tf.keras.models.load_model("FDI_AE_TII.keras")
        print("✅ Model loaded")

        # anomaly thresholds (your calibrated values)
        self.mean_val = 1.2940699484182185
        self.std_dev_val = 0.00844878665634276
        self.th = 1.3006772074498418

        self.batch = []

        # MAGIC header from DPDK
        self.MAGIC = np.uint32(0xAABBCCDD)

    # =========================
    # STREAM READER WITH RESYNC
    # =========================
    def read_stream(self):

        offset = 0

        while True:

            if not os.path.exists(self.file_path):
                time.sleep(0.5)
                continue

            file_size = os.path.getsize(self.file_path)

            # wait for enough new data
            if file_size - offset < 4 + 108:
                time.sleep(0.05)
                continue

            with open(self.file_path, "rb") as f:
                f.seek(offset)

                while True:

                    # -------------------------
                    # READ MAGIC
                    # -------------------------
                    header = f.read(4)
                    if len(header) < 4:
                        break

                    magic = np.frombuffer(header, dtype=np.uint32)[0]

                    # invalid frame → resync
                    if magic != self.MAGIC:
                        offset += 1
                        f.seek(offset)
                        continue

                    # -------------------------
                    # READ 27 FLOATS
                    # -------------------------
                    chunk = f.read(self.feature_size * 4)

                    if len(chunk) < self.feature_size * 4:
                        break

                    offset += 4 + self.feature_size * 4

                    features = np.frombuffer(chunk, dtype=np.float32)

                    if features.shape[0] != self.feature_size:
                        continue

                    yield features

    # =========================
    # MAIN LOOP
    # =========================
    def run(self):

        print(f"📡 Streaming from {self.file_path}")

        for features in self.read_stream():

            # -------------------------
            # PRINT FEATURES
            # -------------------------
            print("\n27 FEATURES:")
            for i, v in enumerate(features):
                print(f"F{i:02d}: {v:.6f}")

            self.batch.append(features)

            # -------------------------
            # RUN INFERENCE
            # -------------------------
            if len(self.batch) == self.batch_size:

                X = np.array(self.batch).reshape(
                    1,
                    self.batch_size,
                    self.feature_size
                )

                X_hat = self.model.predict(X, verbose=0)

                error = np.linalg.norm(X - X_hat, axis=(1, 2))[0]

                ti = (error - self.mean_val) / self.std_dev_val

                print("\n========================")
                print(f"Reconstruction error: {error:.6f}")
                print(f"TI score: {ti:.6f}")

                if ti > self.th:
                    print("🚨 ANOMALY DETECTED")
                else:
                    print("🟢 NORMAL")

                print("========================\n")

                self.batch.clear()


if __name__ == "__main__":
    engine = StreamingInferenceEngine()
    engine.run()
