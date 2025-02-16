import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class GeminiService {
  private apiUrl = 'http://localhost:3000/gemini';

  constructor(private http: HttpClient) { }

  generateContent(question: string, systemMessage: string): Observable<any> {
    return this.http.post(this.apiUrl, { question, systemMessage });
  }
}