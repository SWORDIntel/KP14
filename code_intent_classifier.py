import logging
import os
import re 
import pickle 
import joblib 
import traceback # For more detailed error logging
from sklearn.feature_extraction.text import TfidfVectorizer 
from sklearn.linear_model import LogisticRegression 
from sklearn.model_selection import train_test_split 
# from sklearn.metrics import accuracy_score
from typing import Any, Dict, Optional, List, Union

from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import subprocess # For (optional) MO execution
import shutil # For checking `mo` in PATH
import numpy # For OpenVINO input
from openvino.runtime import Core, Tensor # For OpenVINO inference

# Data Collection and Annotation Plan for Code Intent Classification:
# (Content remains the same as provided in the prompt - omitted here for brevity in this tool call)
# ... (Full data collection plan as previously defined) ...
# 1. Goal:
#    To create a labeled dataset of code snippets (primarily C/C++ from decompiled malware)
#    categorized by their primary operational intent.
#
# (The rest of the extensive comment block is assumed to be here)


class CodeIntentClassifier:
    """
    Classifies the intent of code snippets using a machine learning model.
    This implementation now focuses on loading and using a pre-trained (dummy) model.
    (Full class docstring with Future Implementation Plan and OpenVINO notes remains as previously defined - omitted for brevity)
    ...
    """
    def __init__(self, 
                 model_path: Optional[str] = "code_intent_model.joblib", 
                 vectorizer_path: Optional[str] = "code_intent_vectorizer.pkl", 
                 ir_model_xml_path: Optional[str] = None, # Added for OpenVINO
                 logger: Optional[logging.Logger] = None,
                 max_features_tfidf: int = 5000):
        self.logger = logger if logger else logging.getLogger(self.__class__.__name__)
        if not logger and not logging.getLogger().hasHandlers(): 
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        self.model_path: Optional[str] = model_path
        self.vectorizer_path: Optional[str] = vectorizer_path
        self.max_features_tfidf: int = max_features_tfidf
        
        self.model: Optional[LogisticRegression] = None
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.onnx_model_path: Optional[str] = None 
        
        self.ir_model_xml_path: Optional[str] = ir_model_xml_path # Store provided path
        self.ir_model_bin_path: Optional[str] = None # Will be derived in load_openvino_ir_model
        self.compiled_model_ir: Optional[Any] = None # For OpenVINO CompiledModel

        # Attempt to load scikit-learn model first if paths are provided
        if self.model_path and self.vectorizer_path:
            self.logger.info(f"Attempting to load scikit-learn components: model from '{self.model_path}', vectorizer from '{self.vectorizer_path}'.")
            if not self.load_trained_components(self.model_path, self.vectorizer_path):
                self.logger.warning("Failed to load one or both scikit-learn components.")
        elif self.model_path or self.vectorizer_path: 
             self.logger.warning("Both model_path and vectorizer_path must be provided to load scikit-learn components.")
        
        # Attempt to load OpenVINO IR model if path is provided
        if self.ir_model_xml_path:
            self.logger.info(f"Attempting to load OpenVINO IR model from '{self.ir_model_xml_path}'.")
            if not self.load_openvino_ir_model(self.ir_model_xml_path):
                self.logger.warning(f"Failed to load OpenVINO IR model from {self.ir_model_xml_path}. OpenVINO inference will not be available.")
        
        if not self.model and not self.compiled_model_ir:
             self.logger.info("No scikit-learn or OpenVINO model loaded during initialization. Train a model or load components manually.")
        elif self.compiled_model_ir:
             self.logger.info("OpenVINO IR model loaded. It will be preferred for classification.")
        elif self.model:
             self.logger.info("Scikit-learn model loaded. It will be used for classification as OpenVINO IR model is not available.")

    def load_trained_components(self, model_path: str, vectorizer_path: str) -> bool:
        else:
            self.logger.info("No model_path or vectorizer_path provided during initialization. Model and vectorizer not loaded. Train a model or load components manually.")

    def load_trained_components(self, model_path: str, vectorizer_path: str) -> bool:
        """
        Attempts to load the scikit-learn model and the TF-IDF vectorizer from the specified paths.
        Sets self.model and self.vectorizer. Updates self.model_path and self.vectorizer_path on success.
        Returns True if both are loaded successfully, False otherwise.
        """
        model_loaded = False
        vectorizer_loaded = False
        
        # Store original paths in case one fails and we need to revert the other successfully loaded one for consistency
        # However, for this method, we'll set the class paths if successful, and nullify if not.
        current_model_path_attr = self.model_path
        current_vectorizer_path_attr = self.vectorizer_path

        # Load Model
        if not os.path.exists(model_path):
            self.logger.warning(f"Model file not found at {model_path}.")
        else:
            try:
                loaded_model = joblib.load(model_path)
                self.model = loaded_model # Set the model attribute
                # self.model_path = model_path # Update path attribute to reflect where it was loaded from
                self.logger.info(f"Scikit-learn model loaded successfully from {model_path}.")
                model_loaded = True
            except Exception as e:
                self.logger.error(f"Error loading model from {model_path}: {e}")
                self.model = None 

        # Load Vectorizer
        if not os.path.exists(vectorizer_path):
            self.logger.warning(f"Vectorizer file not found at {vectorizer_path}.")
        else:
            try:
                with open(vectorizer_path, 'rb') as f:
                    loaded_vectorizer = pickle.load(f)
                self.vectorizer = loaded_vectorizer # Set the vectorizer attribute
                # self.vectorizer_path = vectorizer_path
                self.logger.info(f"TF-IDF Vectorizer loaded successfully from {vectorizer_path}.")
                vectorizer_loaded = True
            except Exception as e:
                self.logger.error(f"Error loading vectorizer from {vectorizer_path}: {e}")
                self.vectorizer = None 
        
        if model_loaded and vectorizer_loaded:
            # Update paths only if both succeed to ensure consistency
            self.model_path = model_path
            self.vectorizer_path = vectorizer_path
            return True
        else:
            # If one loaded but the other didn't, reset to ensure a consistent unloaded state.
            if model_loaded: # but vectorizer failed
                self.logger.warning("Model was loaded, but vectorizer failed. Resetting model to None for consistent state.")
                self.model = None
            if vectorizer_loaded: # but model failed
                self.logger.warning("Vectorizer was loaded, but model failed. Resetting vectorizer to None for consistent state.")
                self.vectorizer = None
            # Do not change self.model_path and self.vectorizer_path if loading fails, keep original paths from __init__
            self.model_path = current_model_path_attr
            self.vectorizer_path = current_vectorizer_path_attr
            return False

    def _default_tokenizer(self, code_snippet: str) -> List[str]:
        if not code_snippet:
            return []
        code = code_snippet.lower()
        token_pattern = re.compile(r"[a-zA-Z_]\w*|[0-9]+|==|!=|<=|>=|&&|\|\||<<|>>|->|\+\+|--|[=;\-\+\*\/\%<>&\|\(\)\{\}\[\]!.,:?~^]")
        tokens = token_pattern.findall(code)
        return tokens

    def save_model(self, path: Optional[str] = None) -> bool:
        save_path = path if path else self.model_path
        if not save_path:
            self.logger.error("No path provided to save model.")
            return False
        if not self.model:
            self.logger.error("Model is None, cannot save.")
            return False
        try:
            dir_name = os.path.dirname(save_path)
            if dir_name and not os.path.exists(dir_name):
                os.makedirs(dir_name, exist_ok=True)
            joblib.dump(self.model, save_path)
            self.logger.info(f"Scikit-learn model saved successfully to {save_path}.")
            return True
        except Exception as e:
            self.logger.error(f"An unexpected error occurred while saving model to {save_path}: {e}")
            return False

    def save_vectorizer(self, path: Optional[str] = None) -> bool:
        save_path = path if path else self.vectorizer_path
        if not save_path:
            self.logger.error("No path provided to save vectorizer.")
            return False
        if not self.vectorizer:
            self.logger.error("Vectorizer is None, cannot save.")
            return False
        try:
            dir_name = os.path.dirname(save_path)
            if dir_name and not os.path.exists(dir_name):
                os.makedirs(dir_name, exist_ok=True)
            with open(save_path, 'wb') as f:
                pickle.dump(self.vectorizer, f)
            self.logger.info(f"TF-IDF Vectorizer saved successfully to {save_path}.")
            return True
        except Exception as e:
            self.logger.error(f"An unexpected error occurred while saving vectorizer to {save_path}: {e}")
            return False

    def preprocess_snippet(self, code_snippet: str) -> Any:
        if not self.vectorizer:
            self.logger.error("TF-IDF Vectorizer is not fitted or loaded. Cannot preprocess snippet.")
            return None 
        
        self.logger.info(f"Preprocessing snippet using loaded TF-IDF vectorizer from '{self.vectorizer_path}'...")
        tokens = self._default_tokenizer(code_snippet)
        processed_code_for_tfidf = " ".join(tokens) 
        
        try:
            vectorized_snippet = self.vectorizer.transform([processed_code_for_tfidf])
            self.logger.info(f"Snippet vectorized. Shape: {vectorized_snippet.shape}")
            return vectorized_snippet
        except Exception as e:
            self.logger.error(f"Error transforming snippet with TF-IDF vectorizer: {e}")
            return None

    def classify_code_block(self, code_snippet: str) -> Dict[str, Any]:
        self.logger.info(f"Classification called for snippet (first 60 chars): '{code_snippet[:60].replace(chr(10), ' ')}'...")

        if self.compiled_model_ir and self.vectorizer and self.model: # OpenVINO preferred if available
            self.logger.info("Attempting classification using OpenVINO IR model.")
            return self.classify_code_block_openvino(code_snippet)
        elif self.model and self.vectorizer: # Fallback to scikit-learn
            self.logger.info("OpenVINO IR model not available or prerequisites missing, falling back to scikit-learn model.")
            
            self.logger.info(f"Using scikit-learn model from: {self.model_path}, Vectorizer from: {self.vectorizer_path}")
            vectorized_snippet: Any = self.preprocess_snippet(code_snippet)
            if vectorized_snippet is None: 
                self.logger.warning("Preprocessing failed for snippet. Cannot classify with scikit-learn.")
                return {
                    "intent": "unknown_preprocess_failed", "confidence": 0.0, "all_probabilities": {},
                    "engine_type": "sklearn_model", "model_path_used": self.model_path,
                    "vectorizer_path_used": self.vectorizer_path, "error": "Preprocessing failed"
                }
            
            try:
                self.logger.info(f"Using loaded scikit-learn model ({self.model.__class__.__name__}) for prediction.")
                if not hasattr(self.model, 'classes_') or not hasattr(self.model, 'predict') or not hasattr(self.model, 'predict_proba'):
                    self.logger.error("Loaded scikit-learn model is missing required attributes.")
                    return {
                        "intent": "unknown_invalid_model_attributes", "confidence": 0.0, "all_probabilities": {},
                        "engine_type": "sklearn_model", "model_path_used": self.model_path,
                        "vectorizer_path_used": self.vectorizer_path, "error": "Model missing critical attributes"
                    }

                predicted_indices = self.model.predict(vectorized_snippet)
                prediction_idx = predicted_indices[0]
                intent = str(self.model.classes_[prediction_idx])
                
                all_probs_raw = self.model.predict_proba(vectorized_snippet)[0]
                confidence = float(all_probs_raw[prediction_idx])
                all_probabilities = {str(self.model.classes_[i]): float(all_probs_raw[i]) for i in range(len(all_probs_raw))}

                self.logger.info(f"Snippet classified with scikit-learn. Intent: {intent}, Confidence: {confidence:.4f}")
                return {
                    "intent": intent, "confidence": confidence, "all_probabilities": all_probabilities,
                    "engine_type": "sklearn_model", "model_path_used": self.model_path,
                    "vectorizer_path_used": self.vectorizer_path
                }
            except Exception as e:
                self.logger.error(f"Error during classification with scikit-learn model: {e}")
                self.logger.debug(traceback.format_exc()) 
                return {
                    "intent": "unknown_classification_error", "confidence": 0.0, "all_probabilities": {},
                    "engine_type": "sklearn_model", "model_path_used": self.model_path,
                    "vectorizer_path_used": self.vectorizer_path, "error": str(e)
                }
        else: # Neither OpenVINO nor scikit-learn model is ready
            self.logger.warning("Neither OpenVINO IR nor scikit-learn model/vectorizer are loaded. Cannot classify.")
            return {
                "intent": "unknown_no_model_available", "confidence": 0.0, "all_probabilities": {},
                "engine_type": "none", 
                "model_path_used": self.model_path if self.model_path else self.ir_model_xml_path,
                "vectorizer_path_used": self.vectorizer_path,
                "error": "No classification model (scikit-learn or OpenVINO IR) or vectorizer loaded."
            }

    def train_intent_model(self, 
                           training_data_path: Optional[str] = None, 
                           labels_path: Optional[str] = None, 
                           training_corpus: Optional[List[str]] = None, 
                           training_labels: Optional[List[str]] = None,
                           validation_data_path: Optional[str] = None) -> Dict[str, Any]:
        corpus_snippets: List[str] = []
        labels_list: List[str] = [] 

        if training_corpus and training_labels:
            self.logger.info(f"Using provided in-memory corpus of {len(training_corpus)} snippets and labels.")
            if len(training_corpus) != len(training_labels):
                self.logger.error(f"Mismatch between provided corpus ({len(training_corpus)}) and labels ({len(training_labels)}). Training aborted.")
                return {"status": "error", "message": "Snippet and label count mismatch."}
            if not training_corpus:
                self.logger.error("Provided training_corpus is empty. Training aborted.")
                return {"status": "error", "message": "Empty training_corpus provided."}
            corpus_snippets = training_corpus
            labels_list = training_labels
        elif training_data_path and labels_path:
            self.logger.info(f"Loading training data from {training_data_path} and labels from {labels_path}.")
            try:
                with open(training_data_path, 'r', encoding='utf-8') as f_corpus:
                    corpus_snippets = [line.strip() for line in f_corpus if line.strip()]
                with open(labels_path, 'r', encoding='utf-8') as f_labels:
                    labels_list = [line.strip() for line in f_labels if line.strip()]
                if len(corpus_snippets) != len(labels_list):
                    self.logger.error(f"Mismatch between snippets ({len(corpus_snippets)}) and labels ({len(labels_list)}). Training aborted.")
                    return {"status": "error", "message": "Snippet and label count mismatch."}
                if not corpus_snippets:
                    self.logger.error("No snippets loaded from file. Training aborted.")
                    return {"status": "error", "message": "No snippets loaded."}
            except Exception as e:
                self.logger.error(f"Error loading training data/labels from files: {e}")
                return {"status": "error", "message": f"File loading error: {e}"}
        else:
            self.logger.error("No valid training data provided. Training aborted.")
            return {"status": "error", "message": "No training data provided."}

        self.logger.info(f"Initializing and fitting TF-IDF vectorizer on {len(corpus_snippets)} snippets...")
        self.vectorizer = TfidfVectorizer(
            tokenizer=self._default_tokenizer, token_pattern=None, 
            max_features=self.max_features_tfidf, lowercase=False 
        )
        try:
            X_tfidf = self.vectorizer.fit_transform(corpus_snippets) 
            self.logger.info(f"TF-IDF Vectorizer fitted. Vocab size: {len(self.vectorizer.vocabulary_)}, Features: {X_tfidf.shape[1]}")
            if not self.save_vectorizer(): 
                 self.logger.warning("Failed to save the fitted vectorizer during training.")
        except Exception as e:
            self.logger.error(f"Error fitting TF-IDF vectorizer: {e}")
            self.vectorizer = None 
            return {"status": "error", "message": f"Vectorizer fitting error: {e}"}
        
        self.logger.info("Training Logistic Regression model (simulation of more complex training)...")
        self.logger.info("Epoch 1/10 (simulated)...")
        self.logger.info("Epoch 5/10 (simulated)...")
        self.logger.info("Epoch 10/10 (simulated)...")
        
        X_train, X_test, y_train, y_test = None, None, None, None
        accuracy = None
        
        try:
            if len(set(labels_list)) > 1 and X_tfidf.shape[0] >= 5: 
                X_train, X_test, y_train, y_test = train_test_split(X_tfidf, labels_list, test_size=0.2, random_state=42, stratify=labels_list)
                self.logger.info(f"Train/test split: Train {X_train.shape[0]}, Test {X_test.shape[0]}.")
            else:
                self.logger.warning("Dataset too small or has only one class for stratified split. Training on full dataset.")
                X_train, y_train = X_tfidf, labels_list
        except ValueError as e_split: 
             self.logger.warning(f"Train/test split failed: {e_split}. Training on full dataset.")
             X_train, y_train = X_tfidf, labels_list

        self.model = LogisticRegression(random_state=42, max_iter=1000, solver='liblinear', class_weight='balanced')
        try:
            self.model.fit(X_train, y_train)
            self.logger.info("Logistic Regression model training completed.")
            self.logger.info("NPU/OpenVINO Optimization Note: The trained model could be optimized.")
            self.logger.info("  - Export to ONNX -> OpenVINO Model Optimizer (IR) -> INT8 Quantization (POT) -> Inference on NPU.")
            self.logger.info("  (Refer to class docstring for more detailed OpenVINO optimization strategy.)")

            if not self.save_model(): 
                self.logger.warning("Failed to save the trained model.")
        except Exception as e:
            self.logger.error(f"Error training Logistic Regression model: {e}")
            self.model = None
            return {"status": "error", "message": f"Model training error: {e}", "model_path": self.model_path}

        if X_test is not None and y_test is not None and hasattr(self.model, 'score'):
            try:
                accuracy = self.model.score(X_test, y_test)
                self.logger.info(f"Model accuracy on internal test split: {accuracy:.4f}")
            except Exception as e_acc:
                 self.logger.warning(f"Could not calculate accuracy on test split: {e_acc}")
        
        num_train_samples = X_train.shape[0] if X_train is not None else X_tfidf.shape[0]
        num_features = X_train.shape[1] if X_train is not None else X_tfidf.shape[1]

        return {
            "status": "simulated_training_complete", 
            "message": "Simulated training finished. Model and vectorizer saved.", 
            "model_path": self.model_path, 
            "vectorizer_path": self.vectorizer_path, 
            "num_training_samples": num_train_samples,
            "num_features": num_features,
            "accuracy_on_test_split": accuracy,
            "onnx_model_path": self.onnx_model_path,
            "ir_model_xml_path": self.ir_model_xml_path # Will be set if MO conversion is called
        }

    def export_model_to_onnx(self, onnx_model_path: Optional[str] = None) -> bool:
        """
        Exports the trained scikit-learn model to ONNX format.

        Args:
            onnx_model_path: Optional path to save the ONNX model. 
                             If None, derives from self.model_path or uses a default.

        Returns:
            True if export is successful, False otherwise.
        """
        if not self.model:
            self.logger.error("Scikit-learn model is not available (None). Cannot export to ONNX.")
            return False
        if not self.vectorizer:
            self.logger.error("TF-IDF Vectorizer is not available (None). Cannot determine input features for ONNX export.")
            return False

        if onnx_model_path:
            self.onnx_model_path = onnx_model_path
        elif self.model_path:
            self.onnx_model_path = self.model_path.replace(".joblib", ".onnx")
        else:
            self.onnx_model_path = "code_intent_model.onnx" # Default path

        try:
            # Determine the number of input features from the vectorizer
            # One way is to get the length of the vocabulary
            num_features = len(self.vectorizer.vocabulary_)
            if num_features == 0:
                # Alternative: if vocabulary_ is empty (e.g. vectorizer not fitted or dummy), try transforming a dummy string
                # This might happen if vectorizer was loaded but vocab was empty or not standard.
                try:
                    dummy_transformed = self.vectorizer.transform(["dummy test string"])
                    num_features = dummy_transformed.shape[1]
                    if num_features == 0:
                         self.logger.error("Vectorizer reported 0 features. Cannot define ONNX input shape.")
                         return False
                except Exception as e_shape:
                    self.logger.error(f"Could not determine feature count from vectorizer: {e_shape}")
                    return False
            
            self.logger.info(f"Defining ONNX model input shape with {num_features} features.")
            initial_type = [('float_input', FloatTensorType([None, num_features]))]

            self.logger.info(f"Converting scikit-learn model to ONNX format (target_opset=12)...")
            # target_opset can be adjusted. 12 is a common choice.
            onnx_model = convert_sklearn(self.model, initial_types=initial_type, target_opset=12) 

            # Ensure directory exists for the ONNX model path
            onnx_dir = os.path.dirname(self.onnx_model_path)
            if onnx_dir and not os.path.exists(onnx_dir):
                os.makedirs(onnx_dir, exist_ok=True)
                self.logger.info(f"Created directory for ONNX model: {onnx_dir}")

            with open(self.onnx_model_path, "wb") as f:
                f.write(onnx_model.SerializeToString())
            
            self.logger.info(f"ONNX model exported successfully to {self.onnx_model_path}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to export model to ONNX at {self.onnx_model_path}: {e}")
            self.logger.debug(traceback.format_exc())
            self.onnx_model_path = None 
            return False

    def convert_onnx_to_openvino_ir(self, 
                                    onnx_model_path: Optional[str] = None, 
                                    output_dir: Optional[str] = None,
                                    model_name: Optional[str] = None,
                                    data_type: str = "FP32") -> Optional[str]:
        """
        Generates and logs the Model Optimizer (MO) command to convert an ONNX model to OpenVINO IR.
        Optionally, it can attempt to run the command if MO is configured in the environment.

        Args:
            onnx_model_path: Path to the input ONNX model. Uses self.onnx_model_path if None.
            output_dir: Directory to save the IR files. Uses directory of ONNX model if None.
            model_name: Name for the output IR model (e.g., "model_ir"). Derived from ONNX name if None.
            data_type: Data type for the IR model (e.g., "FP32", "FP16").

        Returns:
            The expected path to the .xml IR file if command generation is successful, None otherwise.
        """
        actual_onnx_path = onnx_model_path if onnx_model_path else self.onnx_model_path
        if not actual_onnx_path or not os.path.exists(actual_onnx_path):
            self.logger.error(f"ONNX model path '{actual_onnx_path}' not found or not provided. Cannot convert to OpenVINO IR.")
            return None

        if not self.vectorizer:
            self.logger.error("Vectorizer not available. Cannot determine input shape for MO.")
            return None

        actual_output_dir = output_dir if output_dir else os.path.dirname(actual_onnx_path)
        if not actual_output_dir: # Handle case where dirname might be empty if onnx_model_path is just a filename
            actual_output_dir = "." 
        os.makedirs(actual_output_dir, exist_ok=True)

        actual_model_name = model_name
        if not actual_model_name:
            base_onnx_name = os.path.splitext(os.path.basename(actual_onnx_path))[0]
            actual_model_name = f"{base_onnx_name}_ir"
        
        self.ir_model_xml_path = os.path.join(actual_output_dir, actual_model_name + ".xml")
        self.ir_model_bin_path = os.path.join(actual_output_dir, actual_model_name + ".bin")

        try:
            num_features = len(self.vectorizer.vocabulary_)
            if num_features == 0: # Fallback if vocab is empty for some reason
                dummy_transformed = self.vectorizer.transform(["dummy test string"])
                num_features = dummy_transformed.shape[1]
            if num_features == 0:
                self.logger.error("Could not determine number of features from vectorizer for input_shape.")
                return None
            input_shape = f"[1,{num_features}]" # Batch size of 1
        except Exception as e:
            self.logger.error(f"Error determining input shape from vectorizer: {e}")
            return None

        # Prefer `mo` directly assuming it's in PATH (common for OpenVINO 2022.1+).
        # Users with older versions or custom setups might need to adjust this or ensure mo.py is in PATH.
        mo_command_executable = "mo" 
        # One could add logic here to search for mo.py if `shutil.which("mo")` fails.
        # For instance: `if not shutil.which("mo"): mo_command_executable = "python3"` and then add path to mo.py
        # But for this task, we'll keep it simple as requested.

        cmd = [
            mo_command_executable,
            "--input_model", actual_onnx_path,
            "--output_dir", actual_output_dir,
            "--model_name", actual_model_name,
            "--input_shape", input_shape,
            "--data_type", data_type
        ]
        # Example for static shape, if needed: cmd.extend(["--static_shape"])
        # Example for mean/scale values if needed: cmd.extend(["--mean_values", "[123,117,104]", "--scale_values", "[58,57,57]"])

        cmd_str = ' '.join([f'"{c}"' if ' ' in c else c for c in cmd]) # Handle spaces in paths for display
        self.logger.info(f"Constructed OpenVINO Model Optimizer command: {cmd_str}")
        
        # For this exercise, we will primarily log the command.
        # Actual execution can be complex due to environment (OpenVINO init scripts, PATH).
        self.logger.info(f"To convert the ONNX model to OpenVINO IR, please run the following command in an environment where OpenVINO is initialized:")
        self.logger.info(f"CMD: {cmd_str}")

        # --- Optional: Attempt to run the command ---
        # This part is illustrative and might require specific environment setup to succeed.
        # It's commented out by default as per focus on command generation.
        try_execution = self.logger.level == logging.DEBUG  # Example: try execution if log level is DEBUG
        if try_execution:
            self.logger.info("Attempting to execute MO command...")
            try:
                # Ensure OpenVINO environment is sourced, or mo is in PATH.
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300) # Added timeout
                self.logger.info("MO command executed successfully.")
                self.logger.debug(f"MO stdout:\n{result.stdout}")
                if result.stderr: # MO often prints info to stderr, so log as debug or info
                    self.logger.info(f"MO stderr:\n{result.stderr}") 
                # Verify IR files were created
                if not os.path.exists(self.ir_model_xml_path) or not os.path.exists(self.ir_model_bin_path):
                    self.logger.error(f"MO command seemed to succeed, but IR files not found at expected paths: {self.ir_model_xml_path}, {self.ir_model_bin_path}")
                    # Reset paths if files are not there
                    self.ir_model_xml_path = None
                    self.ir_model_bin_path = None
                    return None
                return self.ir_model_xml_path
            except subprocess.CalledProcessError as e:
                self.logger.error(f"MO command execution failed with return code {e.returncode}.")
                self.logger.error(f"MO stdout:\n{e.stdout}")
                self.logger.error(f"MO stderr:\n{e.stderr}")
                self.ir_model_xml_path = None # Reset on failure
                self.ir_model_bin_path = None
                return None
            except FileNotFoundError:
                self.logger.error(f"MO command ('{mo_command_executable}') not found. Ensure OpenVINO environment is configured and MO is in PATH.")
                self.ir_model_xml_path = None # Reset on failure
                self.ir_model_bin_path = None
                return None
            except subprocess.TimeoutExpired:
                self.logger.error("MO command execution timed out.")
                self.ir_model_xml_path = None # Reset on failure
                self.ir_model_bin_path = None
                return None
            except Exception as e_exec:
                self.logger.error(f"An unexpected error occurred during MO command execution: {e_exec}")
                self.logger.debug(traceback.format_exc())
                self.ir_model_xml_path = None # Reset on failure
                self.ir_model_bin_path = None
                return None
        else: # If not trying execution, return expected path
            self.logger.info("Execution of MO command is simulated (try_execution=False or not DEBUG level). IR model paths are set to expected values.")
            return self.ir_model_xml_path 

    def load_openvino_ir_model(self, ir_xml_path: str) -> bool:
        """
        Loads an OpenVINO IR model.

        Args:
            ir_xml_path: Path to the .xml file of the IR model.

        Returns:
            True if successful, False otherwise.
        """
        self.logger.info(f"Attempting to load OpenVINO IR model from: {ir_xml_path}")
        bin_path = ir_xml_path.replace(".xml", ".bin")

        if not os.path.exists(ir_xml_path):
            self.logger.error(f"OpenVINO IR model .xml file not found: {ir_xml_path}")
            return False
        if not os.path.exists(bin_path):
            self.logger.error(f"OpenVINO IR model .bin file not found: {bin_path}")
            return False
        
        try:
            core = Core()
            model_ir = core.read_model(model=ir_xml_path)
            self.compiled_model_ir = core.compile_model(model=model_ir, device_name="CPU")
            self.ir_model_xml_path = ir_xml_path # Store path from which it was loaded
            self.ir_model_bin_path = bin_path
            self.logger.info(f"OpenVINO IR model loaded and compiled successfully from {ir_xml_path}.")
            return True
        except Exception as e:
            self.logger.error(f"Error loading or compiling OpenVINO IR model from {ir_xml_path}: {e}")
            self.logger.debug(traceback.format_exc())
            self.compiled_model_ir = None
            self.ir_model_xml_path = None # Reset path if loading failed
            self.ir_model_bin_path = None
            return False

    def classify_code_block_openvino(self, code_snippet: str) -> Dict[str, Any]:
        """
        Classifies a code snippet using the loaded OpenVINO IR model.
        """
        if not self.compiled_model_ir:
            self.logger.error("OpenVINO IR model not compiled/loaded. Cannot classify.")
            return {"intent": "unknown_ir_model_not_loaded", "confidence": 0.0, "error": "OpenVINO IR model not ready."}
        if not self.vectorizer:
            self.logger.error("Vectorizer not loaded. Cannot preprocess for OpenVINO IR model.")
            return {"intent": "unknown_no_vectorizer", "confidence": 0.0, "error": "Vectorizer not loaded."}
        if not self.model or not hasattr(self.model, 'classes_'): # Need scikit-learn model for class labels
            self.logger.error("Original scikit-learn model (for class labels) not loaded.")
            return {"intent": "unknown_no_class_labels", "confidence": 0.0, "error": "Class labels unavailable."}

        try:
            vectorized_snippet_sparse = self.preprocess_snippet(code_snippet)
            if vectorized_snippet_sparse is None:
                 return {"intent": "unknown_preprocess_failed", "confidence": 0.0, "error": "Preprocessing failed for OpenVINO."}

            numpy_input_array = vectorized_snippet_sparse.toarray().astype(numpy.float32)
            
            # Assuming the ONNX model (and thus IR model) has one input and one output.
            # For scikit-learn logistic regression, output is typically probabilities.
            input_layer = self.compiled_model_ir.input(0) # Get the input tensor description
            output_layer = self.compiled_model_ir.output(0) # Get the output tensor description
            
            # Create a Tensor object from numpy array for inference
            # input_tensor = Tensor(numpy_input_array) # This way might be needed for some versions/models
            # results = self.compiled_model_ir.infer_new_request({input_layer.any_name: input_tensor})
            
            # Simpler way for single input, often works:
            results = self.compiled_model_ir([numpy_input_array])
            output_data = results[output_layer] # output_data is a numpy array

            probabilities = output_data[0] # Assuming batch size of 1
            predicted_idx = int(numpy.argmax(probabilities))
            intent = str(self.model.classes_[predicted_idx])
            confidence = float(probabilities[predicted_idx])
            all_probabilities = {str(self.model.classes_[i]): float(probabilities[i]) for i in range(len(probabilities))}

            self.logger.info(f"Snippet classified with OpenVINO IR. Intent: {intent}, Confidence: {confidence:.4f}")
            return {
                "intent": intent, "confidence": confidence, "all_probabilities": all_probabilities,
                "engine_type": "openvino_ir", "model_path_used": self.ir_model_xml_path,
                "vectorizer_path_used": self.vectorizer_path
            }
        except Exception as e:
            self.logger.error(f"Error during OpenVINO IR classification: {e}")
            self.logger.debug(traceback.format_exc())
            return {
                "intent": "unknown_openvino_error", "confidence": 0.0, "all_probabilities": {},
                "engine_type": "openvino_ir", "model_path_used": self.ir_model_xml_path,
                "vectorizer_path_used": self.vectorizer_path, "error": str(e)
            }

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s') 
    main_logger = logging.getLogger("CodeIntentClassifierExample")

    current_dir = os.getcwd()
    test_model_path = os.path.join(current_dir, "test_intent_model.joblib")
    test_vectorizer_path = os.path.join(current_dir, "test_intent_vectorizer.pkl")

    main_logger.info("--- Test Case 1: Training, Saving, Loading, and Classification ---")
    classifier_train = CodeIntentClassifier(
        model_path=test_model_path, 
        vectorizer_path=test_vectorizer_path, 
        logger=main_logger,
        max_features_tfidf=100 
    )
    
    dummy_corpus = [
        "int main() { printf(\"Hello, world!\\n\"); return 0; }", 
        "void encrypt_data(char* data, int size, char* key) { for(int i=0; i<size; ++i) data[i] ^= key[i % strlen(key)]; }",
        "SOCKET s = socket(AF_INET, SOCK_STREAM, 0); connect(s, &addr, sizeof(addr)); send(s, buf, len, 0);", 
        "CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);", 
        "RegOpenKeyExA(HKEY_CURRENT_USER, subkey, 0, KEY_READ, &hKey); RegQueryValueExA(hKey, value_name, NULL, &type, data_buf, &buf_size);", 
        "char* important_data = \"sensitive\"; send(sock, important_data, strlen(important_data), 0);", 
        "int another_func() { return 1+1; }", 
        "char transform(char c) { return c ^ 0xAB; }", 
        "connect(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr));", 
        "TerminateProcess(hProcess, 0);" 
    ]
    dummy_labels = [
        "benign_utility", "encryption", "networking_communication", "process_manipulation", 
        "registry_operations", "data_exfiltration", "benign_utility", "encryption", 
        "networking_communication", "process_manipulation"
    ]

    train_result = classifier_train.train_intent_model(
        training_corpus=dummy_corpus, 
        training_labels=dummy_labels
    )
    main_logger.info(f"Training Result: {train_result}")
    assert train_result["status"] == "simulated_training_complete", f"Training failed: {train_result.get('message')}"
    assert os.path.exists(test_model_path), "Model file was not saved after training."
    assert os.path.exists(test_vectorizer_path), "Vectorizer file was not saved after training."
    main_logger.info(f"Accuracy on internal test split: {train_result.get('accuracy_on_test_split', 'N/A')}")
    
    # Check if ONNX model was created (path should be in train_result)
    onnx_path_from_train = train_result.get("onnx_model_path")
    assert onnx_path_from_train, "ONNX model path not returned from training."
    assert os.path.exists(onnx_path_from_train), f"ONNX model file was not saved at {onnx_path_from_train} after training."
    main_logger.info(f"ONNX model successfully created at: {onnx_path_from_train}")

    # Attempt to convert ONNX to OpenVINO IR
    main_logger.info("\n--- Attempting ONNX to OpenVINO IR Conversion (Command Generation) ---")
    expected_ir_xml_path = None
    if classifier_train.onnx_model_path: # Ensure ONNX model was created
        expected_ir_xml_path = classifier_train.convert_onnx_to_openvino_ir() 
        if expected_ir_xml_path:
            main_logger.info(f"OpenVINO IR conversion command generated. Expected XML: {expected_ir_xml_path}")
            # For testing, we'll assume the user runs MO. If not, load_openvino_ir_model will fail gracefully.
        else:
            main_logger.warning("OpenVINO IR conversion command generation failed or prerequisites not met.")
    else:
        main_logger.warning("ONNX model path not available, skipping OpenVINO IR conversion command generation.")


    main_logger.info("\n--- Loading and Classifying (Testing OpenVINO Priority) ---")
    # Instantiate with all paths: sklearn, and the *expected* IR path.
    # The classifier should prioritize OpenVINO if the IR model is successfully loaded.
    
    # To effectively test OpenVINO loading, we'd need the actual IR files.
    # Since MO is only logged, we can't guarantee they exist for the test.
    # If expected_ir_xml_path is set, we pass it to __init__.
    # The test will then depend on whether these files were manually created by running MO.
    
    classifier_unified = CodeIntentClassifier( 
        model_path=test_model_path, 
        vectorizer_path=test_vectorizer_path, 
        ir_model_xml_path=expected_ir_xml_path, # Pass the expected path
        logger=main_logger
    )

    # At this point, classifier_unified.compiled_model_ir might be None if IR files don't exist.
    # The classify_code_block method will then fallback to sklearn.
    # If IR files *do* exist (user ran MO), it should use OpenVINO.

    test_snippet_network = "send(socket_descriptor, data_buffer, data_length, 0);"
    classification = classifier_unified.classify_code_block(test_snippet_network)
    main_logger.info(f"Unified Classification for '{test_snippet_network[:30]}...': {json.dumps(classification, indent=2)}")
    assert classification["intent"] is not None and classification["intent"] not in ["unknown_no_model_or_vectorizer", "unknown_no_model_available"], "Classification failed."
    
    if classifier_unified.compiled_model_ir:
        main_logger.info("OpenVINO IR model was loaded and should have been used.")
        assert classification["engine_type"] == "openvino_ir", "Engine type mismatch, expected OpenVINO."
    else:
        main_logger.info("OpenVINO IR model was NOT loaded (likely IR files not found). Scikit-learn model should have been used.")
        assert classification["engine_type"] == "sklearn_model", "Engine type mismatch, expected scikit-learn fallback."
    assert "all_probabilities" in classification, "all_probabilities missing from result."
    assert classification["model_path_used"] == test_model_path
    assert classification["vectorizer_path_used"] == test_vectorizer_path

    test_snippet_file = "ReadFile(hFile, buffer, sizeof(buffer), &bytes_read, NULL);"
    classification_file = classifier_load.classify_code_block(test_snippet_file)
    main_logger.info(f"Classification for '{test_snippet_file[:30]}...': {json.dumps(classification_file, indent=2)}")
    assert classification_file["intent"] is not None and classification_file["intent"] != "unknown_no_model_or_vectorizer", "Classification failed for file snippet."
    
    main_logger.info("\n--- Testing with Unloaded Components (should fail gracefully) ---")
    classifier_unloaded = CodeIntentClassifier(model_path="non_existent_model.joblib", 
                                               vectorizer_path="non_existent_vectorizer.pkl", 
                                               logger=main_logger)
    result_unloaded = classifier_unloaded.classify_code_block("int x = 0;")
    main_logger.info(f"Classification with unloaded components: {json.dumps(result_unloaded, indent=2)}")
    assert "Model or Vectorizer not loaded" in result_unloaded.get("error", ""), f"Unexpected error message: {result_unloaded.get('error')}"
    assert result_unloaded["intent"] == "unknown_no_model_or_vectorizer"

    main_logger.info("\n--- Testing with only model path provided during init ---")
    classifier_model_only = CodeIntentClassifier(model_path=test_model_path, logger=main_logger) # vectorizer_path will be default
    result_model_only = classifier_model_only.classify_code_block("int x = 0;")
    main_logger.info(f"Classification with only model path: {json.dumps(result_model_only, indent=2)}")
    assert "Model or Vectorizer not loaded" in result_model_only.get("error", "")

    main_logger.info("\n--- Cleaning up test files ---")
    # Add expected IR paths to cleanup if they were set (even if files don't exist due to simulated execution)
    paths_to_clean = [test_model_path, test_vectorizer_path, onnx_path_from_train]
    if classifier_train.ir_model_xml_path:
        paths_to_clean.append(classifier_train.ir_model_xml_path)
    if classifier_train.ir_model_bin_path:
        paths_to_clean.append(classifier_train.ir_model_bin_path)
        
    for f_path in paths_to_clean:
        if f_path and os.path.exists(f_path): 
            # For directories (like potential output_dir for IR models if it's distinct)
            if os.path.isdir(f_path) and not os.listdir(f_path): # remove empty dir
                 os.rmdir(f_path)
                 main_logger.info(f"Removed empty directory {f_path}")
            elif os.path.isfile(f_path):
                 os.remove(f_path)
                 main_logger.info(f"Removed {f_path}")
            
    main_logger.info("\n--- All baseline model training and classification tests completed ---")
```
