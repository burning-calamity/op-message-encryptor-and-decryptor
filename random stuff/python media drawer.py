import turtle
from tkinter import Tk, filedialog, simpledialog
from PIL import Image
import cv2
import numpy as np
import multiprocessing as mp
import math
import time
import queue


# ================================
# TURTLE MOVEMENT
# ================================

def move_to_origin(t, w, h, scale):
    t.home()
    t.penup()
    t.backward((w * scale) / 2)
    t.left(90)
    t.forward((h * scale) / 2)
    t.right(90)


def move_to_point(t, x, y, w, h, scale):

    move_to_origin(t, w, h, scale)

    t.setheading(0)
    t.forward(x * scale)

    t.setheading(-90)
    t.forward(y * scale)

    t.setheading(0)


def draw_polygon(t, pts, color, w, h, scale):

    if len(pts) < 3:
        return

    pts_scaled = [(p[0]*scale, p[1]*scale) for p in pts]
    pts_scaled.append(pts_scaled[0])

    move_to_point(t, pts[0][0], pts[0][1], w, h, scale)

    t.pencolor(color)
    t.fillcolor(color)

    t.pendown()
    t.begin_fill()

    prevx, prevy = pts_scaled[0]

    for x,y in pts_scaled[1:]:

        dx = x - prevx
        dy = y - prevy

        angle = math.degrees(math.atan2(-dy, dx))
        dist = math.hypot(dx, dy)

        t.setheading(angle)
        t.forward(dist)

        prevx, prevy = x,y

    t.end_fill()
    t.penup()


# ================================
# IMAGE RESIZE
# ================================

def resize_frame(frame, width):

    ratio = width / frame.shape[1]

    return cv2.resize(
        frame,
        (width, int(frame.shape[0] * ratio))
    )


# ================================
# BINARY ULTRA FAST MODE
# ================================

def extract_binary_regions(frame):

    gray = cv2.cvtColor(frame, cv2.COLOR_RGB2GRAY)

    _, thresh = cv2.threshold(gray,127,255,cv2.THRESH_BINARY)

    contours,_ = cv2.findContours(
        thresh,
        cv2.RETR_EXTERNAL,
        cv2.CHAIN_APPROX_SIMPLE
    )

    regions = []

    for cnt in contours:

        if len(cnt) >= 3:

            pts = [(int(p[0][0]), int(p[0][1])) for p in cnt]

            regions.append((pts,(0,0,0)))

    return regions


# ================================
# FAST COLOR REGION EXTRACTION
# ================================

def extract_color_regions(frame):

    reduced = (frame // 16) * 16

    regions = []

    colors = np.unique(reduced.reshape(-1,3), axis=0)

    for color in colors:

        mask = cv2.inRange(reduced, color, color)

        kernel = np.ones((3,3),np.uint8)

        mask = cv2.morphologyEx(mask,cv2.MORPH_CLOSE,kernel)

        contours,_ = cv2.findContours(
            mask,
            cv2.RETR_EXTERNAL,
            cv2.CHAIN_APPROX_SIMPLE
        )

        for cnt in contours:

            if len(cnt) >= 3:

                pts = [(int(p[0][0]), int(p[0][1])) for p in cnt]

                regions.append((pts,tuple(int(c) for c in color)))

    return regions


# ================================
# VIDEO PRODUCER
# ================================

def producer(video_path,width,binary_mode,frame_queue):

    cap = cv2.VideoCapture(video_path)

    while True:

        ret,frame = cap.read()

        if not ret:
            break

        frame = cv2.cvtColor(frame,cv2.COLOR_BGR2RGB)

        frame = resize_frame(frame,width)

        if binary_mode:
            regions = extract_binary_regions(frame)
        else:
            regions = extract_color_regions(frame)

        h,w = frame.shape[:2]

        frame_queue.put((regions,w,h))

    frame_queue.put(None)

    cap.release()


# ================================
# MAIN PROGRAM
# ================================

if __name__ == "__main__":

    mp.freeze_support()

    root = Tk()
    root.withdraw()

    path = filedialog.askopenfilename(
        title="Select image or video",
        filetypes=[("Media","*.png *.jpg *.jpeg *.bmp *.gif *.mp4 *.avi *.mov *.mkv")]
    )

    if not path:
        exit()

    is_video = path.lower().endswith((".mp4",".avi",".mov",".mkv"))

    binary_input = simpledialog.askstring(
        "Binary Mode",
        "Type 'binary' for ultra fast mode\nPress Enter for color mode"
    )

    binary_mode = binary_input and binary_input.lower()=="binary"

    unstable_input = simpledialog.askstring(
        "Framerate",
        "Type 'unstable' for adaptive FPS\nPress Enter for fixed FPS"
    )

    unstable_mode = unstable_input and unstable_input.lower()=="unstable"

    if not unstable_mode:

        target_fps = simpledialog.askinteger(
            "FPS",
            "Desired FPS",
            initialvalue=8
        )

    width = simpledialog.askinteger(
        "Width",
        "Rendering width",
        initialvalue=160
    )

    scale = 3

    screen = turtle.Screen()
    screen.colormode(255)
    screen.tracer(0,0)

    t = turtle.Turtle()
    t.hideturtle()
    t.speed(0)
    t.penup()

    fps_history = []


    # ================================
    # IMAGE MODE
    # ================================

    if not is_video:

        img = Image.open(path).convert("RGB")

        frame = np.array(img)

        frame = resize_frame(frame,width)

        if binary_mode:
            regions = extract_binary_regions(frame)
        else:
            regions = extract_color_regions(frame)

        h,w = frame.shape[:2]

        screen.setup(w*scale+80, h*scale+80)

        if regions:

            for item in regions:

                if len(item)==2:

                    pts,color = item

                    draw_polygon(t,pts,color,w,h,scale)

        screen.update()

        turtle.done()


    # ================================
    # VIDEO MODE
    # ================================

    else:

        frame_queue = mp.Queue(maxsize=6)

        proc = mp.Process(
            target=producer,
            args=(path,width,binary_mode,frame_queue)
        )

        proc.start()

        frame_data = frame_queue.get()

        if frame_data is None:
            exit()

        regions,w,h = frame_data

        screen.setup(w*scale+80, h*scale+80)

        while True:

            t.clear()

            start = time.time()

            if regions:

                for item in regions:

                    if len(item)==2:

                        pts,color = item

                        draw_polygon(t,pts,color,w,h,scale)

            screen.update()

            elapsed = time.time() - start

            if unstable_mode:

                fps = 1/elapsed if elapsed>0 else 0

                fps_history.append(fps)

                if len(fps_history) > 8:
                    fps_history.pop(0)

                avg = sum(fps_history)/len(fps_history)

                print("Adaptive FPS:",round(avg,2))

            else:

                sleep_time = max(0,(1/target_fps)-elapsed)

                time.sleep(sleep_time)

            try:

                frame_data = frame_queue.get(timeout=5)

            except queue.Empty:

                break

            if frame_data is None:
                break

            regions,w,h = frame_data

        proc.join()

        turtle.done()
