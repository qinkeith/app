import { Component, ViewChild, ElementRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { GeminiService } from '../services/gemini.service';

interface ChatMessage {
  content: string;
  type: 'user' | 'gemini' | 'error';
  isHtml?: boolean;
}

@Component({
  selector: 'app-chat',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatInputModule,
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule
  ],
  templateUrl: './chat.component.html',
  styleUrls: ['./chat.component.scss']
})
export class ChatComponent {
  @ViewChild('chatContainer') private chatContainer!: ElementRef;

  messages: ChatMessage[] = [];
  question: string = '';
  systemMessage: string = '';

  constructor(private geminiService: GeminiService) {}

  async sendQuestion() {
    if (!this.question.trim()) {
      alert('Please enter a question.');
      return;
    }

    if (!this.systemMessage.trim()) {
      alert('Please enter a system message.');
      return;
    }

    // Add user message to chat
    this.messages.push({
      content: this.question,
      type: 'user'
    });

    try {
      const response = await this.geminiService
        .generateContent(this.question, this.systemMessage)
        .toPromise();

      // Add Gemini's response to chat
      this.messages.push({
        content: response.response,
        type: 'gemini',
        isHtml: true
      });

      // Clear input
      this.question = '';
      
      // Scroll to bottom
      setTimeout(() => {
        this.scrollToBottom();
      });
    } catch (error: unknown) {
      console.error('Error:', error);
      let errorMessage = 'An error occurred';
      
      if (error instanceof Error) {
        errorMessage = error.message;
      } else if (typeof error === 'string') {
        errorMessage = error;
      }

      this.messages.push({
        content: `Error: ${errorMessage}`,
        type: 'error'
      });
    }
  }

  private scrollToBottom(): void {
    try {
      this.chatContainer.nativeElement.scrollTop = 
        this.chatContainer.nativeElement.scrollHeight;
    } catch(err) {}
  }
}
