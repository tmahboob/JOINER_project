import os
import time
import struct
import csv

import numpy as np
import tensorflow as tf


class StreamingInferenceEngine:

    # =========================================================
    # CONFIG
    # =========================================================

    DEBUG = False

    DEFAULT_FILE_PATH = "/tmp/dpdk_modbus_features.bin"

    DEFAULT_MODEL_PATH = "FDI_AE_TII.keras"

    DEFAULT_LATENCY_CSV = "/tmp/inference_latency.csv"

    # =========================================================
    # INIT
    # =========================================================

    def __init__(
        self,
        file_path=DEFAULT_FILE_PATH,
        model_path=DEFAULT_MODEL_PATH,
        latency_csv=DEFAULT_LATENCY_CSV,
        batch_size=12,
        feature_size=27,
    ):

        self.file_path = file_path
        self.model_path = model_path
        self.latency_csv = latency_csv

        self.batch_size = batch_size
        self.feature_size = feature_size

        # =====================================================
        # FILE FORMAT
        #
        # 4 bytes   = MAGIC
        # 108 bytes = 27 x float32
        #
        # TOTAL = 112 bytes
        # =====================================================

        self.magic = 0xAABBCCDD

        self.magic_bytes = struct.pack(
            "<I",
            self.magic
        )

        self.record_size = (
            4 +
            self.feature_size * 4
        )

        self.offset = 0

        # =====================================================
        # BATCH
        # =====================================================

        self.batch = []

        self.batch_record_ids = []

        # =====================================================
        # COUNTERS
        # =====================================================

        self.total_records = 0

        self.total_batches = 0

        self.total_anomalies = 0

        # =====================================================
        # CALIBRATION
        # =====================================================

        self.mean_val = 1.2940699484182185

        self.std_dev_val = 0.00844878665634276

        self.th = 1.3006772074498418

        # =====================================================
        # LOAD MODEL
        # =====================================================

        print("⏳ Loading model...")

        self.model = tf.keras.models.load_model(
            self.model_path
        )

        print("✅ Model loaded")

        # =====================================================
        # MODEL INPUT
        #
        # Expected:
        #
        # (1, 12, 27)
        # =====================================================

        self.model_input_shape = (
            1,
            self.batch_size,
            self.feature_size
        )

        # =====================================================
        # BUILD TF INFERENCE FUNCTION
        # =====================================================

        self.infer_fn = (
            self._build_inference_function()
        )

        # =====================================================
        # WARM-UP
        #
        # The first TensorFlow execution can contain:
        #
        # - graph creation
        # - kernel initialization
        # - memory allocation
        #
        # Therefore it must NOT be included in the
        # latency measurements.
        # =====================================================

        print("🔥 Warming up TensorFlow...")

        warmup = np.zeros(
            self.model_input_shape,
            dtype=np.float32
        )

        warmup_tensor = tf.convert_to_tensor(
            warmup,
            dtype=tf.float32
        )

        warmup_output = self.infer_fn(
            warmup_tensor
        )

        # Force TensorFlow execution to finish.
        _ = warmup_output.numpy()

        print("✅ TensorFlow warm-up complete")

        # =====================================================
        # CREATE LATENCY CSV
        # =====================================================

        self.init_latency_csv()

        # =====================================================
        # INFORMATION
        # =====================================================

        print()
        print("=" * 70)
        print("Streaming Inference Engine")
        print("=" * 70)

        print(
            f"Feature file      : "
            f"{self.file_path}"
        )

        print(
            f"Model             : "
            f"{self.model_path}"
        )

        print(
            f"Latency CSV       : "
            f"{self.latency_csv}"
        )

        print(
            f"Feature size      : "
            f"{self.feature_size}"
        )

        print(
            f"Batch size        : "
            f"{self.batch_size}"
        )

        print(
            f"Record size       : "
            f"{self.record_size} bytes"
        )

        print(
            f"Magic             : "
            f"0x{self.magic:08X}"
        )

        print(
            "Magic bytes       : "
            +
            " ".join(
                f"{b:02X}"
                for b in self.magic_bytes
            )
        )

        print(
            f"Model input       : "
            f"{self.model.input_shape}"
        )

        print(
            f"Model output      : "
            f"{self.model.output_shape}"
        )

        print()

        print(
            f"Mean error        : "
            f"{self.mean_val:.12f}"
        )

        print(
            f"Std deviation     : "
            f"{self.std_dev_val:.12f}"
        )

        print(
            f"TI threshold      : "
            f"{self.th:.12f}"
        )

        print("=" * 70)

    # =========================================================
    # BUILD TF INFERENCE FUNCTION
    # =========================================================

    def _build_inference_function(self):

        input_spec = tf.TensorSpec(
            shape=(
                1,
                self.batch_size,
                self.feature_size
            ),
            dtype=tf.float32
        )

        @tf.function(
            input_signature=[input_spec],
            reduce_retracing=True
        )
        def infer(x):

            return self.model(
                x,
                training=False
            )

        return infer

    # =========================================================
    # CREATE LATENCY CSV
    # =========================================================

    def init_latency_csv(self):

        try:

            self.latency_fp = open(
                self.latency_csv,
                "w",
                newline=""
            )

        except OSError as e:

            raise RuntimeError(
                f"Cannot create latency CSV "
                f"{self.latency_csv}: {e}"
            )

        self.csv_writer = csv.writer(
            self.latency_fp
        )

        self.csv_writer.writerow(
            [
                "batch_id",
                "first_record_id",
                "last_record_id",
                "records",

                "inference_ns",
                "inference_us",
                "inference_ms",

                "per_packet_us",
                "per_packet_ms",

                "squared_sum",
                "l2_norm",
                "reconstruction_error",

                "mse",
                "rmse",
                "mae",

                "mean_error",
                "std_deviation",

                "ti_score",
                "ti_threshold",

                "predicted_label",
            ]
        )

        self.latency_fp.flush()

    # =========================================================
    # CLOSE LATENCY CSV
    # =========================================================

    def close_latency_csv(self):

        if hasattr(
            self,
            "latency_fp"
        ):

            try:

                self.latency_fp.flush()

                self.latency_fp.close()

            except Exception:

                pass

    # =========================================================
    # FIND NEXT MAGIC
    # =========================================================

    def find_magic(
        self,
        f,
        start_offset
    ):

        f.seek(
            start_offset
        )

        buffer = b""

        search_offset = (
            start_offset
        )

        while True:

            chunk = f.read(
                4096
            )

            if not chunk:

                return None

            buffer += chunk

            position = buffer.find(
                self.magic_bytes
            )

            if position >= 0:

                return (
                    search_offset +
                    position
                )

            if len(buffer) > 3:

                search_offset += (
                    len(buffer) - 3
                )

                buffer = buffer[-3:]

    # =========================================================
    # READ ONE RECORD
    # =========================================================

    def read_record_at(
        self,
        f,
        offset
    ):

        f.seek(
            offset
        )

        data = f.read(
            self.record_size
        )

        # -----------------------------------------------------
        # No data
        # -----------------------------------------------------

        if len(data) == 0:

            return None, offset

        # -----------------------------------------------------
        # Partial record
        # -----------------------------------------------------

        if len(data) < self.record_size:

            return None, offset

        # -----------------------------------------------------
        # MAGIC
        # -----------------------------------------------------

        magic = struct.unpack_from(
            "<I",
            data,
            0
        )[0]

        if magic != self.magic:

            if self.DEBUG:

                print()
                print(
                    "⚠️ BAD MAGIC"
                )

                print(
                    f"Offset   : {offset}"
                )

                print(
                    f"Found    : "
                    f"0x{magic:08X}"
                )

                print(
                    f"Expected : "
                    f"0x{self.magic:08X}"
                )

                print(
                    "🔎 Searching "
                    "for next record..."
                )

            next_magic = self.find_magic(
                f,
                offset + 1
            )

            if next_magic is None:

                return None, offset

            if self.DEBUG:

                print(
                    f"✅ Next magic at byte "
                    f"{next_magic}"
                )

            return None, next_magic

        # -----------------------------------------------------
        # FLOAT DATA
        #
        # Offset 4
        #
        # 27 x little-endian float32
        # -----------------------------------------------------

        features = np.frombuffer(
            data,
            dtype="<f4",
            offset=4,
            count=self.feature_size
        ).copy()

        next_offset = (
            offset +
            self.record_size
        )

        return (
            features,
            next_offset
        )

    # =========================================================
    # PRINT FEATURES
    # =========================================================

    def print_features(
        self,
        features
    ):

        if not self.DEBUG:

            return

        print()
        print(
            "----------------------------------------"
        )

        print(
            "27 FEATURES"
        )

        print(
            "----------------------------------------"
        )

        for i, value in enumerate(
            features
        ):

            print(
                f"F{i:02d}: "
                f"{value: .9f}"
            )

        print(
            "----------------------------------------"
        )

        print(
            f"min  : "
            f"{np.min(features):.9f}"
        )

        print(
            f"max  : "
            f"{np.max(features):.9f}"
        )

        print(
            f"mean : "
            f"{np.mean(features):.9f}"
        )

        print(
            f"std  : "
            f"{np.std(features):.9f}"
        )

        print(
            "----------------------------------------"
        )

    # =========================================================
    # RUN INFERENCE
    # =========================================================

    def run_inference(self):

        if len(self.batch) != self.batch_size:

            return

        # =====================================================
        # BATCH ID
        # =====================================================

        batch_id = (
            self.total_batches + 1
        )

        first_record_id = (
            self.batch_record_ids[0]
        )

        last_record_id = (
            self.batch_record_ids[-1]
        )

        # =====================================================
        # CONVERT BATCH
        #
        # (12,27)
        # =====================================================

        X = np.asarray(
            self.batch,
            dtype=np.float32
        )

        expected_shape = (
            self.batch_size,
            self.feature_size
        )

        if X.shape != expected_shape:

            print()
            print(
                "❌ INVALID BATCH SHAPE"
            )

            print(
                f"Expected : "
                f"{expected_shape}"
            )

            print(
                f"Received : "
                f"{X.shape}"
            )

            self.batch.clear()

            self.batch_record_ids.clear()

            return

        # =====================================================
        # RESHAPE
        #
        # (12,27)
        #
        #       ↓
        #
        # (1,12,27)
        # =====================================================

        X = X.reshape(
            1,
            self.batch_size,
            self.feature_size
        )

        if self.DEBUG:

            print()
            print(
                "========================================"
            )

            print(
                "🧠 RUNNING INFERENCE"
            )

            print(
                "========================================"
            )

            print(
                f"Batch ID : "
                f"{batch_id}"
            )

            print(
                f"Records  : "
                f"{first_record_id} -> "
                f"{last_record_id}"
            )

            print(
                f"X shape  : "
                f"{X.shape}"
            )

            print(
                f"X dtype  : "
                f"{X.dtype}"
            )

            print(
                f"X min    : "
                f"{X.min():.9f}"
            )

            print(
                f"X max    : "
                f"{X.max():.9f}"
            )

            print(
                f"X mean   : "
                f"{X.mean():.9f}"
            )

            print(
                f"X std    : "
                f"{X.std():.9f}"
            )

        # =====================================================
        # TENSORFLOW INPUT
        # =====================================================

        X_tensor = tf.convert_to_tensor(
            X,
            dtype=tf.float32
        )

        # =====================================================
        # INFERENCE TIMING
        #
        # Only the TensorFlow model execution is timed.
        #
        # .numpy() forces execution to complete before the
        # timer stops, which is important for GPU execution.
        # =====================================================

        start_ns = (
            time.perf_counter_ns()
        )

        X_hat_tensor = self.infer_fn(
            X_tensor
        )

        X_hat = (
            X_hat_tensor.numpy()
        )

        end_ns = (
            time.perf_counter_ns()
        )

        # =====================================================
        # LATENCY
        # =====================================================

        inference_ns = (
            end_ns -
            start_ns
        )

        inference_us = (
            inference_ns /
            1000.0
        )

        inference_ms = (
            inference_ns /
            1_000_000.0
        )

        # Amortized cost per packet.
        #
        # IMPORTANT:
        # This is not actual packet latency.
        # It is batch inference cost divided by 12.

        per_packet_us = (
            inference_us /
            self.batch_size
        )

        per_packet_ms = (
            inference_ms /
            self.batch_size
        )

        # =====================================================
        # MODEL OUTPUT DEBUG
        # =====================================================

        if self.DEBUG:

            print()
            print(
                "========================================"
            )

            print(
                "MODEL OUTPUT"
            )

            print(
                "========================================"
            )

            print(
                f"X shape     : "
                f"{X.shape}"
            )

            print(
                f"X_hat shape : "
                f"{X_hat.shape}"
            )

            print(
                f"X dtype     : "
                f"{X.dtype}"
            )

            print(
                f"X_hat dtype : "
                f"{X_hat.dtype}"
            )

            print(
                f"X_hat min   : "
                f"{np.min(X_hat):.9f}"
            )

            print(
                f"X_hat max   : "
                f"{np.max(X_hat):.9f}"
            )

            print(
                f"X_hat mean  : "
                f"{np.mean(X_hat):.9f}"
            )

            print(
                f"X_hat std   : "
                f"{np.std(X_hat):.9f}"
            )

        # =====================================================
        # ERROR
        # =====================================================

        diff = (
            X -
            X_hat
        )

        squared_sum = float(
            np.sum(
                diff ** 2
            )
        )

        l2_norm = float(
            np.linalg.norm(
                diff
            )
        )

        errors2 = np.linalg.norm(
            diff,
            axis=(1, 2)
        )

        error = float(
            errors2[0]
        )

        mse = float(
            np.mean(
                diff ** 2
            )
        )

        rmse = float(
            np.sqrt(
                mse
            )
        )

        mae = float(
            np.mean(
                np.abs(diff)
            )
        )

        # =====================================================
        # TI SCORE
        # =====================================================

        ti = (
            error -
            self.mean_val
        ) / self.std_dev_val

        # =====================================================
        # CLASSIFICATION
        # =====================================================

        predicted_label = (
            1
            if ti > self.th
            else 0
        )

        if predicted_label == 1:

            self.total_anomalies += 1

        # =====================================================
        # WRITE CSV
        # =====================================================

        self.csv_writer.writerow(
            [
                batch_id,

                first_record_id,

                last_record_id,

                self.batch_size,

                inference_ns,

                f"{inference_us:.6f}",

                f"{inference_ms:.6f}",

                f"{per_packet_us:.6f}",

                f"{per_packet_ms:.6f}",

                f"{squared_sum:.9f}",

                f"{l2_norm:.9f}",

                f"{error:.9f}",

                f"{mse:.12f}",

                f"{rmse:.12f}",

                f"{mae:.12f}",

                f"{self.mean_val:.12f}",

                f"{self.std_dev_val:.12f}",

                f"{ti:.9f}",

                f"{self.th:.9f}",

                predicted_label,
            ]
        )

        # =====================================================
        # FLUSH CSV
        #
        # Flush every batch so the file remains useful while
        # the program is running.
        # =====================================================

        self.latency_fp.flush()

        # =====================================================
        # CONSOLE
        # =====================================================

        print(
            f"\r"
            f"Batch {batch_id:8d} | "
            f"records "
            f"{first_record_id}-"
            f"{last_record_id} | "
            f"inference "
            f"{inference_us:10.3f} us | "
            f"per-packet "
            f"{per_packet_us:10.3f} us | "
            f"TI "
            f"{ti:10.4f} | "
            f"label "
            f"{predicted_label}",
            end="",
            flush=True
        )

        # =====================================================
        # DEBUG DETAILS
        # =====================================================

        if self.DEBUG:

            print()

            print(
                "========================================"
            )

            print(
                "RECONSTRUCTION ERROR"
            )

            print(
                "========================================"
            )

            print(
                f"Squared sum          : "
                f"{squared_sum:.9f}"
            )

            print(
                f"L2 norm              : "
                f"{l2_norm:.9f}"
            )

            print(
                f"Reconstruction error : "
                f"{error:.9f}"
            )

            print(
                f"MSE                  : "
                f"{mse:.12f}"
            )

            print(
                f"RMSE                 : "
                f"{rmse:.12f}"
            )

            print(
                f"MAE                  : "
                f"{mae:.12f}"
            )

            print(
                f"TI score             : "
                f"{ti:.9f}"
            )

            print(
                f"TI threshold         : "
                f"{self.th:.9f}"
            )

            print(
                f"Predicted label      : "
                f"{predicted_label}"
            )

            if predicted_label == 1:

                print(
                    "🚨 ANOMALY DETECTED"
                )

            else:

                print(
                    "🟢 NORMAL"
                )

        # =====================================================
        # COUNTERS
        # =====================================================

        self.total_batches += 1

        # =====================================================
        # CLEAR BATCH
        # =====================================================

        self.batch.clear()

        self.batch_record_ids.clear()

    # =========================================================
    # STREAM
    # =========================================================

    def run(self):

        print()
        print(
            "🚀 Starting streaming inference"
        )

        print(
            f"📡 Streaming from "
            f"{self.file_path}"
        )

        print(
            f"📊 Latency CSV: "
            f"{self.latency_csv}"
        )

        print()

        try:

            while True:

                # =================================================
                # FILE EXISTENCE
                # =================================================

                if not os.path.exists(
                    self.file_path
                ):

                    print(
                        f"\r📂 Waiting for: "
                        f"{self.file_path}",
                        end="",
                        flush=True
                    )

                    time.sleep(
                        0.5
                    )

                    continue

                # =================================================
                # FILE SIZE
                # =================================================

                try:

                    file_size = (
                        os.path.getsize(
                            self.file_path
                        )
                    )

                except OSError:

                    time.sleep(
                        0.1
                    )

                    continue

                # =================================================
                # DETECT FILE RESET
                # =================================================

                if file_size < self.offset:

                    print()

                    print(
                        "🔄 FILE RESET DETECTED"
                    )

                    print(
                        f"Old offset : "
                        f"{self.offset}"
                    )

                    print(
                        f"New size   : "
                        f"{file_size}"
                    )

                    self.offset = 0

                    self.batch.clear()

                    self.batch_record_ids.clear()

                # =================================================
                # AVAILABLE DATA
                # =================================================

                available = (
                    file_size -
                    self.offset
                )

                # =================================================
                # WAIT FOR COMPLETE RECORD
                # =================================================

                if available < self.record_size:

                    if self.DEBUG:

                        print(
                            f"\r"
                            f"file_size="
                            f"{file_size} | "
                            f"offset="
                            f"{self.offset} | "
                            f"available="
                            f"{available}",
                            end="",
                            flush=True
                        )

                    time.sleep(
                        0.02
                    )

                    continue

                # =================================================
                # OPEN FEATURE FILE
                # =================================================

                try:

                    with open(
                        self.file_path,
                        "rb"
                    ) as f:

                        while True:

                            # =====================================
                            # CHECK FILE SIZE AGAIN
                            # =====================================

                            try:

                                current_size = (
                                    os.path.getsize(
                                        self.file_path
                                    )
                                )

                            except OSError:

                                break

                            available = (
                                current_size -
                                self.offset
                            )

                            if (
                                available <
                                self.record_size
                            ):

                                break

                            # =====================================
                            # READ RECORD
                            # =====================================

                            old_offset = (
                                self.offset
                            )

                            features, next_offset = (
                                self.read_record_at(
                                    f,
                                    self.offset
                                )
                            )

                            # =====================================
                            # INVALID / PARTIAL
                            # =====================================

                            if features is None:

                                if (
                                    next_offset
                                    != old_offset
                                ):

                                    self.offset = (
                                        next_offset
                                    )

                                break

                            # =====================================
                            # VALID RECORD
                            # =====================================

                            self.offset = (
                                next_offset
                            )

                            record_id = (
                                self.total_records
                            )

                            self.total_records += 1

                            if self.DEBUG:

                                print()

                                print(
                                    "================================"
                                )

                                print(
                                    "📦 VALID FEATURE RECORD"
                                )

                                print(
                                    f"Record : "
                                    f"{record_id}"
                                )

                                print(
                                    f"Offset : "
                                    f"{old_offset}"
                                )

                                print(
                                    f"Next   : "
                                    f"{self.offset}"
                                )

                                print(
                                    f"Size   : "
                                    f"{self.record_size} bytes"
                                )

                                print(
                                    "================================"
                                )

                            # =====================================
                            # PRINT FEATURES
                            # =====================================

                            self.print_features(
                                features
                            )

                            # =====================================
                            # ADD TO BATCH
                            # =====================================

                            self.batch.append(
                                features
                            )

                            self.batch_record_ids.append(
                                record_id
                            )

                            if self.DEBUG:

                                print(
                                    f"📦 Batch: "
                                    f"{len(self.batch)}/"
                                    f"{self.batch_size}"
                                )

                            # =====================================
                            # RUN INFERENCE
                            # =====================================

                            if (
                                len(self.batch)
                                == self.batch_size
                            ):

                                self.run_inference()

                except Exception as e:

                    print()

                    print(
                        f"❌ Reader error: {e}"
                    )

                    time.sleep(
                        0.5
                    )

        except KeyboardInterrupt:

            print()

            print(
                "\n🛑 Stopping inference engine..."
            )

        finally:

            self.close_latency_csv()

            print()

            print(
                "========================================"
            )

            print(
                "INFERENCE SUMMARY"
            )

            print(
                "========================================"
            )

            print(
                f"Feature records : "
                f"{self.total_records}"
            )

            print(
                f"Batches         : "
                f"{self.total_batches}"
            )

            print(
                f"Anomalies       : "
                f"{self.total_anomalies}"
            )

            print(
                f"Latency CSV     : "
                f"{self.latency_csv}"
            )

            print(
                "========================================"
            )


# =============================================================
# MAIN
# =============================================================

if __name__ == "__main__":

    engine = StreamingInferenceEngine()

    engine.run()
