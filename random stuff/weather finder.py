#do not use this to dox people please
"script made for my friend terminus boy on roblox, he probably changed his user for the 50th time so I will adress him through his nickname"
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta
from meteostat import Stations, Daily
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading, os
from urllib.error import URLError
from PIL import Image, ImageTk  # pip install pillow

# ---- rough ISO→name for search ----
ISO_TO_NAME = {
    "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AR": "Argentina",
    "AU": "Australia", "AT": "Austria", "BE": "Belgium", "BA": "Bosnia and Herzegovina",
    "BR": "Brazil", "BG": "Bulgaria", "CA": "Canada", "CL": "Chile", "CN": "China",
    "CO": "Colombia", "CR": "Costa Rica", "HR": "Croatia", "CY": "Cyprus",
    "CZ": "Czechia", "DK": "Denmark", "DO": "Dominican Republic", "EG": "Egypt",
    "EE": "Estonia", "FI": "Finland", "FR": "France", "DE": "Germany",
    "GR": "Greece", "HK": "Hong Kong", "HU": "Hungary", "IS": "Iceland",
    "IN": "India", "ID": "Indonesia", "IE": "Ireland", "IL": "Israel",
    "IT": "Italy", "JP": "Japan", "JO": "Jordan", "KR": "South Korea",
    "LV": "Latvia", "LT": "Lithuania", "LU": "Luxembourg", "MY": "Malaysia",
    "MX": "Mexico", "ME": "Montenegro", "MA": "Morocco", "NL": "Netherlands",
    "NZ": "New Zealand", "NG": "Nigeria", "NO": "Norway", "PK": "Pakistan",
    "PA": "Panama", "PE": "Peru", "PH": "Philippines", "PL": "Poland",
    "PT": "Portugal", "RO": "Romania", "RU": "Russia", "SA": "Saudi Arabia",
    "RS": "Serbia", "SG": "Singapore", "SK": "Slovakia", "SI": "Slovenia",
    "ZA": "South Africa", "ES": "Spain", "SE": "Sweden", "CH": "Switzerland",
    "TW": "Taiwan", "TH": "Thailand", "TR": "Türkiye", "TN": "Tunisia",
    "UA": "Ukraine", "GB": "United Kingdom", "US": "United States",
    "UY": "Uruguay", "VN": "Vietnam"
}

# ----------------- weather mapping -----------------
def text_to_condition_fn(text):
    text = text.lower().strip()

    def is_rain(row): return (row.get('prcp') or 0) > 0
    def is_snow(row): return (row.get('snow') or 0) > 0
    def is_clear(row): return (row.get('prcp') or 0) == 0
    def is_storm(row): return (row.get('prcp') or 0) >= 5

    if "rain" in text:
        return is_rain
    if "snow" in text:
        return is_snow
    if "clear" in text or "sun" in text:
        return is_clear
    if "storm" in text:
        return is_storm
    return lambda r: True


# ----------------- station check -----------------
def fetch_daily_safe(station_id, start_dt, end_dt, retries=2):
    last_err = None
    for _ in range(retries):
        try:
            return Daily(station_id, start_dt, end_dt).fetch()
        except (URLError, OSError) as e:
            last_err = e
    if last_err:
        raise last_err


def station_satisfies_all_and_temps(station_id, conditions, day_window):
    """
    Returns (True, temps_list) if station satisfies all conditions.
    temps_list = [
        {"cond_line": "...", "date": "YYYY-MM-DD", "tavg": ..., "tmin": ..., "tmax": ...},
        ...
    ]
    else (False, None)
    """
    collected = []
    for cond in conditions:
        base_date = cond["date"]
        cond_fn = cond["cond_fn"]
        raw_line = cond["raw"]

        start_dt = datetime.combine(base_date - timedelta(days=day_window), datetime.min.time())
        end_dt = datetime.combine(base_date + timedelta(days=day_window), datetime.min.time())

        data = fetch_daily_safe(station_id, start_dt, end_dt)
        if data.empty:
            return False, None

        matched_day = None
        for idx, row in data.iterrows():
            if cond_fn(row.to_dict()):
                matched_day = (idx, row)
                break

        if not matched_day:
            return False, None

        day_idx, day_row = matched_day
        d = day_idx.date().isoformat()
        day_dict = day_row.to_dict()
        collected.append({
            "cond_line": raw_line,
            "date": d,
            "tavg": day_dict.get("tavg"),
            "tmin": day_dict.get("tmin"),
            "tmax": day_dict.get("tmax"),
        })

    return True, collected


def _station_worker(st_id, name, lat, lon, conditions, day_window):
    ok, temps = station_satisfies_all_and_temps(st_id, conditions, day_window)
    if ok:
        return {
            "city": name,
            "station": st_id,
            "lat": lat,
            "lon": lon,
            "temps": temps,  # list per condition
        }
    return None


def find_matches_parallel(stations_df, conditions, day_window, max_workers):
    matches = []
    futures = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for _, row in stations_df.iterrows():
            st_id = row.name
            name = row.get("name", "unknown")
            lat = row.get("latitude")
            lon = row.get("longitude")
            futures.append(ex.submit(_station_worker, st_id, name, lat, lon, conditions, day_window))
        for fut in as_completed(futures):
            res = fut.result()
            if res is not None:
                matches.append(res)
    return matches


# ----------------- GUI -----------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Meteostat multi-date weather finder (worldwide, searchable, map bg, temps)")
        self.geometry("1200x700")

        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=0)

        # preload stations
        self.all_stations_cache = Stations().fetch(6000)
        all_codes = sorted(set(self.all_stations_cache["country"].dropna().astype(str).tolist()))
        self.country_records = [(code, ISO_TO_NAME.get(code, "")) for code in all_codes]

        # left panel
        left = ttk.Frame(self, padding=10)
        left.grid(row=0, column=0, rowspan=2, sticky="nsw")

        ttk.Label(left, text="Country:").pack(anchor="w")
        self.country_search_var = tk.StringVar()
        self.country_search = ttk.Entry(left, textvariable=self.country_search_var, width=26)
        self.country_search.pack(anchor="w")
        self.country_search_var.trace_add("write", self.on_country_search)

        self.country_listbox = tk.Listbox(left, height=10, width=28)
        self.country_listbox.pack(anchor="w", pady=(0, 5))
        self.country_listbox.bind("<<ListboxSelect>>", self.on_country_select)

        self.fill_country_listbox(self.country_records)
        self.selected_country_code = self.country_records[0][0] if self.country_records else "GB"

        ttk.Label(left, text="± days:").pack(anchor="w")
        self.window_var = tk.StringVar(value="3")
        ttk.Entry(left, textvariable=self.window_var, width=6).pack(anchor="w", pady=(0, 5))

        ttk.Label(left, text="Max workers:").pack(anchor="w")
        self.workers_var = tk.StringVar(value="8")
        ttk.Entry(left, textvariable=self.workers_var, width=6).pack(anchor="w", pady=(0, 10))

        ttk.Label(left, text="Conditions (YYYY-MM-DD: weather):").pack(anchor="w")
        self.cond_text = tk.Text(left, height=10, width=28)
        self.cond_text.insert("1.0", "2024-07-21: rain\n2024-08-30: clear\n")
        self.cond_text.pack(anchor="w", pady=(0, 10))

        self.run_btn = ttk.Button(left, text="Run", command=self.on_run)
        self.run_btn.pack(anchor="w", pady=2)
        ttk.Button(left, text="Clear output", command=self.on_clear).pack(anchor="w", pady=2)

        # output panel
        out_frame = ttk.LabelFrame(self, text="Output", padding=10)
        out_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        out_frame.rowconfigure(0, weight=1)
        out_frame.columnconfigure(0, weight=1)

        self.output = tk.Text(out_frame, wrap="word")
        self.output.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(out_frame, orient="vertical", command=self.output.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.output.configure(yscrollcommand=scroll.set)

        # map panel
        map_frame = ttk.LabelFrame(self, text="Stations map (with country bg if available)", padding=5)
        map_frame.grid(row=0, column=2, rowspan=2, sticky="nsew", padx=5, pady=5)
        map_frame.rowconfigure(0, weight=1)
        map_frame.columnconfigure(0, weight=1)

        self.map_canvas = tk.Canvas(map_frame, bg="white")
        self.map_canvas.grid(row=0, column=0, sticky="nsew")
        self.map_canvas.bind("<Configure>", self.on_map_resize)

        self.map_tooltip = tk.Label(self.map_canvas, bg="yellow", fg="black")
        self.map_canvas.bind("<Motion>", self.on_map_motion)

        self.last_plotted = []
        self._last_matches_for_redraw = []
        self._bg_image = None  # keep ref

    # ---------- country search ----------
    def fill_country_listbox(self, records):
        self.country_listbox.delete(0, "end")
        for code, name in records:
            display = f"{code}  {name}" if name else code
            self.country_listbox.insert("end", display)

    def on_country_search(self, *args):
        term = self.country_search_var.get().strip().lower()
        if not term:
            self.fill_country_listbox(self.country_records)
            return
        filtered = []
        for code, name in self.country_records:
            if term in code.lower() or (name and term in name.lower()):
                filtered.append((code, name))
        self.fill_country_listbox(filtered)

    def on_country_select(self, event):
        sel = self.country_listbox.curselection()
        if not sel:
            return
        item_text = self.country_listbox.get(sel[0])
        iso = item_text.split()[0]
        self.selected_country_code = iso
        # redraw bg if we already have results
        if self._last_matches_for_redraw:
            self.draw_map(self._last_matches_for_redraw)
        else:
            self.draw_map([])

    # ---------- helpers ----------
    def log(self, text):
        self.output.insert("end", text)
        self.output.see("end")
        self.update_idletasks()

    def on_clear(self):
        self.output.delete("1.0", "end")
        self.map_canvas.delete("all")
        self.last_plotted = []
        self._last_matches_for_redraw = []
        self._bg_image = None

    def parse_conditions(self, raw_text):
        lines = [l.strip() for l in raw_text.strip().splitlines() if l.strip()]
        conds = []
        for line in lines:
            if ":" not in line:
                raise ValueError(f"bad line (missing ':'): {line}")
            left, right = line.split(":", 1)
            date_str = left.strip()
            weather_txt = right.strip()
            date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
            conds.append({
                "date": date_obj,
                "cond_fn": text_to_condition_fn(weather_txt),
                "raw": line
            })
        return conds

    # ---------- run ----------
    def on_run(self):
        country = self.selected_country_code
        raw = self.cond_text.get("1.0", "end")

        try:
            window = int(self.window_var.get().strip())
        except ValueError:
            window = 1

        try:
            max_workers = int(self.workers_var.get().strip())
            if max_workers < 1:
                max_workers = 1
        except ValueError:
            max_workers = 8

        try:
            conds = self.parse_conditions(raw)
        except Exception as e:
            messagebox.showerror("error", str(e))
            return

        self.log("-------------------------------------------------\n")
        self.log(f"country={country}, ±{window} days, workers={max_workers}\n")
        for c in conds:
            self.log(f" - {c['date']}: {c['raw'].split(':',1)[1].strip()}\n")

        self.run_btn.config(state="disabled")

        def background_job():
            try:
                stations_df = self.all_stations_cache[self.all_stations_cache["country"] == country.upper()]
                if stations_df.empty:
                    raise RuntimeError(f"no stations for country {country}")
                matches = find_matches_parallel(
                    stations_df,
                    conds,
                    day_window=window,
                    max_workers=max_workers
                )
            except Exception as ex:
                self.after(0, lambda err=ex: self._job_error(err))
                return
            self.after(0, lambda m=matches: self._job_done(m))

        threading.Thread(target=background_job, daemon=True).start()

    def _job_error(self, e):
        self.log(f"[error] {e}\n")
        messagebox.showerror("error", str(e))
        self.run_btn.config(state="normal")

    def _job_done(self, matches):
        if not matches:
            self.log("no station met ALL conditions\n")
            self.map_canvas.delete("all")
            self.last_plotted = []
            self._last_matches_for_redraw = []
        else:
            self.log(f"{len(matches)} stations met ALL conditions:\n")
            for m in matches:
                self.log(f"- {m['city']} ({m['station']})\n")
                # print temps
                for tt in m.get("temps", []):
                    self.log(
                        f"    {tt['cond_line']} -> {tt['date']} | "
                        f"tavg={tt['tavg']}°C tmin={tt['tmin']}°C tmax={tt['tmax']}°C\n"
                    )
            self._last_matches_for_redraw = matches
            self.draw_map(matches)
        self.run_btn.config(state="normal")

    # ---------- map ----------
    def on_map_resize(self, event):
        if self._last_matches_for_redraw:
            self.draw_map(self._last_matches_for_redraw)
        else:
            self.draw_map([])

    def load_country_image(self, code, w, h):
        base = os.path.join("maps", code.upper())
        for ext in (".png", ".gif"):
            path = base + ext
            if os.path.exists(path):
                img = Image.open(path).resize((w, h))
                return ImageTk.PhotoImage(img)
        return None

    def draw_map(self, stations):
        self.map_canvas.delete("all")
        self.last_plotted = []

        w = max(int(self.map_canvas.winfo_width()), 200)
        h = max(int(self.map_canvas.winfo_height()), 200)

        # background
        bg_img = self.load_country_image(self.selected_country_code, w, h)
        if bg_img is not None:
            self._bg_image = bg_img
            self.map_canvas.create_image(0, 0, image=self._bg_image, anchor="nw")
        else:
            self.map_canvas.create_rectangle(0, 0, w, h, fill="#eef2f4", outline="gray")
            self.map_canvas.create_text(
                10, 10,
                text=f"{self.selected_country_code} (no map)",
                anchor="nw",
                fill="black"
            )

        if not stations:
            return

        lats = [s["lat"] for s in stations if s["lat"] is not None]
        lons = [s["lon"] for s in stations if s["lon"] is not None]
        if not lats or not lons:
            return

        min_lat, max_lat = min(lats), max(lats)
        min_lon, max_lon = min(lons), max(lons)
        pad = 20

        def proj(lat, lon):
            if max_lon == min_lon:
                x_norm = 0.5
            else:
                x_norm = (lon - min_lon) / (max_lon - min_lon)
            if max_lat == min_lat:
                y_norm = 0.5
            else:
                y_norm = (max_lat - lat) / (max_lat - min_lat)
            x = pad + x_norm * (w - 2 * pad)
            y = pad + y_norm * (h - 2 * pad)
            return x, y

        for s in stations:
            lat = s["lat"]
            lon = s["lon"]
            if lat is None or lon is None:
                continue
            x, y = proj(lat, lon)
            r = 4
            self.map_canvas.create_oval(x - r, y - r, x + r, y + r, fill="red", outline="black")
            # keep a small sample of temps for tooltip (first condition)
            first_temp = None
            temps = s.get("temps") or []
            if temps:
                t0 = temps[0]
                first_temp = {
                    "cond": t0["cond_line"],
                    "date": t0["date"],
                    "tavg": t0["tavg"],
                    "tmin": t0["tmin"],
                    "tmax": t0["tmax"],
                }
            self.last_plotted.append({
                "x": x,
                "y": y,
                "city": s["city"],
                "station": s["station"],
                "lat": lat,
                "lon": lon,
                "first_temp": first_temp,
            })

    def on_map_motion(self, event):
        px, py = event.x, event.y
        radius = 7
        found = None
        for p in self.last_plotted:
            if abs(p["x"] - px) <= radius and abs(p["y"] - py) <= radius:
                found = p
                break
        if found:
            tt = found.get("first_temp")
            if tt:
                temp_line = f"\n{tt['date']} {tt['cond']} tavg={tt['tavg']}°C"
                if tt["tmin"] is not None or tt["tmax"] is not None:
                    temp_line += f" (min={tt['tmin']}°C, max={tt['tmax']}°C)"
            else:
                temp_line = ""
            text = f"{found['city']} ({found['station']})\n{found['lat']:.3f}, {found['lon']:.3f}{temp_line}"
            self.map_tooltip.config(text=text)
            self.map_tooltip.place(x=px + 10, y=py + 10)
        else:
            self.map_tooltip.place_forget()


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
