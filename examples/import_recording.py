#!/usr/bin/env python3
"""
observation-qa — ჩანაწერის იმპორტის მაგალითი Python-ზე
=======================================================

ეს სკრიპტი აჩვენებს, როგორ გადავცეთ უკვე მზა აუდიო ჩანაწერი + ტექსტური
ტრანსკრიფცია (თქვენი საკუთარი voice-recording/transcription პაიფლაინიდან)
observation-qa პლატფორმაზე, რომელიც შემდეგ Gemini-ით გაუშვებს შეფასებას
მოცემული ტრანსკრიფციის მიხედვით (ხელახლა არ გატრანსკრიფცირდება).

გამოყენებამდე:
  1. შედით პლატფორმაზე ადმინის ანგარიშით → „პარამეტრები“ → „API იმპორტის
     გასაღები“ → „ახალი გასაღების გენერაცია“ და დააკოპირეთ გასაღები.
  2. ჩასვით ის ქვემოთ API_KEY ცვლადში (ან წაიკითხეთ გარემოს ცვლადიდან).
  3. `pip install requests`

გაშვება:
  python3 import_recording.py
"""

import os
import requests

# ---------------------------------------------------------------------------
# კონფიგურაცია
# ---------------------------------------------------------------------------

BASE_URL = os.environ.get("OBSERVATION_QA_URL", "http://localhost:3000")
API_KEY = os.environ.get("OBSERVATION_QA_API_KEY", "ჩასვით-აქ-თქვენი-გასაღები")


def import_recording(
    audio_path: str,
    transcript: str,
    employee_name: str,
    branch_name: str,
    note: str | None = None,
    recorded_at: str | None = None,
    template_ids: list[int] | None = None,
) -> dict:
    """
    აგზავნის ერთ აუდიო ჩანაწერს + მისი ტრანსკრიფციას პლატფორმაზე.

    Parameters
    ----------
    audio_path : str
        აუდიო ფაილის ლოკალური გზა (mp3/wav/m4a/aac/ogg/flac/webm/opus/aiff).
    transcript : str
        უკვე მზა ტრანსკრიფცია (თქვენი Python პაიფლაინის შედეგი).
        ეს ტექსტი გადაეცემა Gemini-ს პირდაპირ შეფასებისთვის — ხელახლა
        არ გატრანსკრიფცირდება.
    employee_name : str
        თანამშრომლის სრული სახელი, ზუსტად ისე როგორც პლატფორმაზეა
        რეგისტრირებული (მაგ. "გიორგი გიორგაძე"). შედარება
        რეგისტრირდება/სივრცეებზე დამოუკიდებლად (ზედმეტი spaces
        და დიდი/პატარა ასოები არ აქვს მნიშვნელობა).
    branch_name : str
        ფილიალის სახელი, ზუსტად ისე როგორც პლატფორმაზეა (მაგ. "თბილისი").
    note : str, optional
        თავისუფალი ტექსტის შენიშვნა ჩანაწერზე.
    recorded_at : str, optional
        ჩანაწერის რეალური თარიღი/დრო ISO ფორმატში
        (მაგ. "2026-09-10T14:30:00"). თუ არ მიუთითეთ, გამოიყენება
        სერვერზე ატვირთვის მომენტი.
    template_ids : list[int], optional
        კონკრეტული შეფასების შაბლონების ID-ები, რომლებითაც გნებავთ
        შეფასება. თუ არ მიუთითეთ, გამოიყენება პლატფორმის
        "ავტომატური შეფასების" პარამეტრებში შერჩეული ნაგულისხმევი
        შაბლონები (თუ ისინი დაყენებულია).

    Returns
    -------
    dict
        სერვერის პასუხი: {"id": <recording_id>, "employee_matched": bool,
        "branch_matched": bool}
    """
    url = f"{BASE_URL}/api/import/recording"
    headers = {"X-API-Key": API_KEY}

    data = {
        "transcript": transcript,
        "employee_name": employee_name,
        "branch_name": branch_name,
    }
    if note:
        data["note"] = note
    if recorded_at:
        data["recorded_at"] = recorded_at
    if template_ids:
        import json
        data["template_ids"] = json.dumps(template_ids)

    with open(audio_path, "rb") as f:
        files = {"audio": (os.path.basename(audio_path), f)}
        response = requests.post(url, headers=headers, data=data, files=files, timeout=60)

    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = import_recording(
        audio_path="example_call.mp3",
        transcript=(
            "თანამშრომელი: გამარჯობა, რით შემიძლია დაგეხმაროთ?\n"
            "მომხმარებელი: ლეპტოპი მინდა ვნახო.\n"
            "თანამშრომელი: რა ბიუჯეტს განიხილავთ?\n"
            "..."
        ),
        employee_name="გიორგი გიორგაძე",
        branch_name="თბილისი",
        note="იმპორტირებულია ავტომატური voice-pipeline-იდან",
    )
    print(result)
    # მაგ: {'id': 42, 'employee_matched': True, 'branch_matched': True}
    #
    # თუ 'employee_matched' ან 'branch_matched' არის False, ჩანაწერი მაინც
    # შეინახება (თანამშრომელი/ფილიალის გარეშე), მაგრამ ამ ფაქტს პლატფორმა
    # ავტომატურად ჩაწერს ჩანაწერის შენიშვნაში, რომ არაფერი დაიკარგოს —
    # პლატფორმაზე შეგიძლიათ ხელით მიაბათ სწორ თანამშრომელს/ფილიალს.
