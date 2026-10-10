from detection import DetectionEngine

engine = DetectionEngine()
text = "Name: Priya Nair, SSN 123-45-6789, card ending in 4417, EMP-38104"

for f in engine.detect_text(text):
    print(f.entity_type, f.text, f.confidence)