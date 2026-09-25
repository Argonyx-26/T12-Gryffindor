# Sample Video Directory

Place your test video file here named `sample.mp4`:
`data/sample.mp4`

### Quick Testing Options:
1. **Using any local MP4 video:**
   Download or copy a pedestrian/surveillance video into this folder and rename it `sample.mp4`.
   
2. **Testing with your Webcam:**
   You can run the vision worker directly using your connected webcam:
   ```bash
   python ai/vision_worker.py --video 0
   ```

3. **Specifying a custom video path:**
   ```bash
   python ai/vision_worker.py --video path/to/your_video.mp4
   ```
